"""
FinetunedBackend — DeBERTa fine-tuned multi-label threat classifier (Stage 13).

Loads the trained DeBERTa model from ml/artifacts/nlp_model/.
The model can be loaded from a local checkpoint directory or a Hugging Face
Hub model ID configured through NLP_FINETUNED_PATH. If weights are unavailable
or inference fails, transparently falls back to the deterministic rules backend.
"""

from __future__ import annotations

import asyncio
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


@lru_cache(maxsize=1)
def _load_model() -> tuple[Any, Any] | None:
    """Load a local or Hugging Face fine-tuned checkpoint once per process."""
    from app.core.config import settings

    configured_source = os.getenv(
        "NLP_FINETUNED_PATH", settings.NLP_FINETUNED_PATH
    ).strip()
    model_source = configured_source or str(_DEFAULT_ARTIFACT_DIR)
    model_path = Path(model_source).expanduser()
    is_local_checkpoint = model_path.is_dir()
    looks_like_local_path = (
        model_path.is_absolute()
        or model_source.startswith((".", "~"))
        or "\\" in model_source
    )

    if looks_like_local_path and not is_local_checkpoint:
        logger.warning("Configured local DeBERTa checkpoint directory does not exist: %s", model_path)
        return None

    if is_local_checkpoint:
        has_weights = any((model_path / filename).is_file() for filename in _WEIGHT_FILENAMES)
        has_weights = has_weights or any(model_path.glob("model-*.safetensors"))
        has_weights = has_weights or any(model_path.glob("pytorch_model-*.bin"))
        if not has_weights:
            logger.warning("No fine-tuned model weights found in %s", model_path)
            return None
    elif not configured_source:
        # Do not mistake the checked-in config/tokenizer metadata for trained weights.
        logger.info("No fine-tuned checkpoint configured; expected model weights in %s", model_path)
        return None

    try:
        import torch
        from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer

        load_options = {"local_files_only": is_local_checkpoint}
        hf_token = os.getenv("HF_TOKEN")
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


def ensure_model_loaded() -> bool:
    """Warm the configured checkpoint; report False so callers can use rules."""
    if _load_model() is not None:
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
