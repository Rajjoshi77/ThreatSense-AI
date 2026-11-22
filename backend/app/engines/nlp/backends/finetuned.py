"""
FinetunedBackend — DeBERTa fine-tuned multi-label threat classifier (Stage 13).

Loads the trained DeBERTa model from ml/artifacts/nlp_model/.
The model can be loaded from a local checkpoint directory or a Hugging Face
Hub model ID configured through NLP_FINETUNED_PATH. If weights are unavailable
or inference fails, transparently falls back to the deterministic rules backend.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.engines.nlp.backends.base import SignalBackend
from app.schemas.schemas import NLPSignals

logger = logging.getLogger(__name__)

# Find repository root
def _find_repo_root() -> Path:
    current = Path(__file__).resolve()
    for p in current.parents:
        if (p / "ml").exists() and (p / "backend").exists():
            return p
    return Path.cwd()

_ROOT = _find_repo_root()
_DEFAULT_ARTIFACT_DIR = _ROOT / "ml" / "artifacts" / "nlp_model"
_WEIGHT_FILENAMES = ("model.safetensors", "pytorch_model.bin")

SIGNAL_LABELS = [
    "urgency",
    "fear",
    "authority",
    "reward_scarcity",
    "financial_intent",
    "credential_request",
    "manipulation",
    "phishing_intent",
    "scam_intent",
    "investment_context",
    "recruitment_context",
    "tech_support_context",
    "government_service_claim",
    "payment_request",
    "remote_access_request",
]


def _container_memory_limit_bytes() -> int | None:
    """Return the container memory limit from cgroups when available."""
    for path in (Path("/sys/fs/cgroup/memory.max"), Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")):
        try:
            value = path.read_text(encoding="ascii").strip()
            if value != "max":
                limit = int(value)
                # cgroup v1 reports a large sentinel value when no memory cap exists.
                if limit < (1 << 60):
                    return limit
        except (OSError, ValueError):
            continue
    return None


@lru_cache(maxsize=1)
def _load_model() -> tuple[Any, Any] | None:
    """Load a fine-tuned checkpoint when the container has sufficient memory."""
    from app.core.config import settings

    memory_limit = _container_memory_limit_bytes()
    minimum_memory = settings.NLP_MIN_MEMORY_MB * 1024 * 1024
    if memory_limit is not None and memory_limit < minimum_memory:
        logger.warning(
            "Skipping DeBERTa checkpoint: container memory limit is %d MiB; "
            "NLP_MIN_MEMORY_MB=%d. Using rules NLP fallback.",
            memory_limit // (1024 * 1024),
            settings.NLP_MIN_MEMORY_MB,
        )
        return None

    configured_source = os.getenv(
        "NLP_FINETUNED_PATH", settings.NLP_FINETUNED_PATH
    ).strip()
    model_source = configured_source or str(_DEFAULT_ARTIFACT_DIR)
    model_path = Path(model_source).expanduser()
    is_local_checkpoint = model_path.is_dir()
    hub_model_id = (
        model_source.count("/") == 1
        and not model_source.startswith((".", "~"))
        and not model_path.is_absolute()
        and "\\" not in model_source
    )
    looks_like_local_path = (
        model_path.is_absolute()
        or model_source.startswith((".", "~"))
        or "\\" in model_source
    )

    if looks_like_local_path and not is_local_checkpoint:
        logger.warning("Configured local DeBERTa checkpoint directory does not exist: %s", model_path)
        return None

    if not (is_local_checkpoint or hub_model_id):
        logger.warning(
            "Skipping DeBERTa checkpoint reference %r; expected an existing local directory "
            "or a Hugging Face owner/model ID.",
            model_source,
        )
        return None

    hf_token = os.getenv("HF_TOKEN")
    if is_local_checkpoint:
        metadata_path = model_path / "model.meta.json"
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "Skipping DeBERTa checkpoint without readable training provenance at %s: %s",
                metadata_path,
                exc,
            )
            return None

        has_weights = any((model_path / filename).is_file() for filename in _WEIGHT_FILENAMES)
        has_weights = has_weights or any(model_path.glob("model-*.safetensors"))
        has_weights = has_weights or any(model_path.glob("pytorch_model-*.bin"))
        if not has_weights:
            logger.warning("No fine-tuned model weights found in %s", model_path)
            return None
    else:
        try:
            from huggingface_hub import hf_hub_download

            metadata_path = Path(hf_hub_download(
                repo_id=model_source,
                filename="model.meta.json",
                token=hf_token,
            ))
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning(
                "Skipping Hugging Face DeBERTa checkpoint without readable training provenance: %s",
                exc,
            )
            return None

    training_data = str(metadata.get("training_data", "")).lower()
    if training_data != "human_labeled":
        logger.warning(
            "Skipping DeBERTa checkpoint with unverified training provenance (%s); "
            "using rules NLP fallback.",
            training_data or "missing metadata",
        )
        return None

    try:
        import torch
        from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer

        load_options = {"local_files_only": is_local_checkpoint}
        if hf_token:
            load_options["token"] = hf_token
        logger.info("Loading fine-tuned DeBERTa model from %s", model_source)
        model_config = AutoConfig.from_pretrained(model_source, **load_options)
        if model_config.num_labels != len(SIGNAL_LABELS):
            raise ValueError(
                f"Expected {len(SIGNAL_LABELS)} output labels, got {model_config.num_labels}"
            )
        configured_labels = [
            model_config.id2label.get(index, model_config.id2label.get(str(index)))
            for index in range(len(SIGNAL_LABELS))
        ]
        if configured_labels != SIGNAL_LABELS:
            raise ValueError(
                "Checkpoint label order does not match the ThreatSense signal schema. "
                f"Expected {SIGNAL_LABELS}; got {configured_labels}"
            )
        try:
            tokenizer = AutoTokenizer.from_pretrained(
                model_source, use_fast=True, **load_options
            )
        except Exception:
            logger.warning(
                "Fast tokenizer unavailable for %s; using the slower tokenizer",
                model_source,
                exc_info=True,
            )
            tokenizer = AutoTokenizer.from_pretrained(
                model_source, use_fast=False, **load_options
            )
        model = AutoModelForSequenceClassification.from_pretrained(
            model_source, config=model_config, **load_options
        )
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()
        logger.info("DeBERTa threat model loaded on %s.", device)
        return tokenizer, model
    except Exception:
        logger.exception("Failed to load fine-tuned DeBERTa model from %s", model_source)
        return None


def is_finetuned_available() -> bool:
    """Return whether the configured DeBERTa checkpoint loaded successfully."""
    return _load_model() is not None


def ensure_model_loaded() -> bool:
    """Warm the configured checkpoint; report False so callers can use rules."""
    if is_finetuned_available():
        return True

    from app.core.config import settings

    model_source = os.getenv(
        "NLP_FINETUNED_PATH", settings.NLP_FINETUNED_PATH
    ).strip() or str(_DEFAULT_ARTIFACT_DIR)
    logger.warning(
        "Fine-tuned DeBERTa is unavailable at %s; falling back to rules NLP. "
        "Set NLP_FINETUNED_PATH to a complete trained checkpoint to enable the model.",
        model_source,
    )
    return False


class FinetunedBackend(SignalBackend):
    """DeBERTa fine-tuned multi-label threat classifier."""

    @property
    def backend_name(self) -> str:
        return "finetuned"

    async def analyze(self, text: str) -> NLPSignals:
        bundle = _load_model()
        if bundle is None:
            return await self._rules_fallback(text, "checkpoint unavailable")

        tokenizer, model = bundle
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(None, self._predict, tokenizer, model, text)
        except Exception as exc:
            logger.exception("Fine-tuned DeBERTa inference failed; using rules fallback")
            return await self._rules_fallback(text, f"inference failed: {exc}")

    async def _rules_fallback(self, text: str, reason: str) -> NLPSignals:
        logger.warning("Using rules NLP fallback (%s)", reason)
        from app.engines.nlp.backends.rules import RulesBackend

        return await RulesBackend().analyze(text)

    def _predict(self, tokenizer: Any, model: Any, text: str) -> NLPSignals:
        import torch

        device = next(model.parameters()).device
        max_length = min(256, getattr(model.config, "max_position_embeddings", 512))
        inputs = tokenizer(
            text,
            max_length=max_length,
            truncation=True,
            padding=True,
            return_tensors="pt",
        ).to(device)

        with torch.inference_mode():
            logits = model(**inputs).logits
            probs = torch.sigmoid(logits).squeeze(0).cpu().numpy()

        scores = {sig: round(float(probs[i]), 4) for i, sig in enumerate(SIGNAL_LABELS)}

        return NLPSignals(
            urgency=scores.get("urgency", 0.0),
            fear=scores.get("fear", 0.0),
            authority=scores.get("authority", 0.0),
            reward_scarcity=scores.get("reward_scarcity", 0.0),
            financial_intent=scores.get("financial_intent", 0.0),
            credential_request=scores.get("credential_request", 0.0),
            manipulation=scores.get("manipulation", 0.0),
            phishing_intent=scores.get("phishing_intent", 0.0),
            scam_intent=scores.get("scam_intent", 0.0),
            investment_context=scores.get("investment_context", 0.0),
            recruitment_context=scores.get("recruitment_context", 0.0),
            tech_support_context=scores.get("tech_support_context", 0.0),
            government_service_claim=scores.get("government_service_claim", 0.0),
            payment_request=scores.get("payment_request", 0.0),
            remote_access_request=scores.get("remote_access_request", 0.0),
            backend_used="finetuned",
            text_length=len(text),
        )
