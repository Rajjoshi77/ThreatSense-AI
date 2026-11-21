"""
FinetunedBackend — DeBERTa fine-tuned multi-label threat classifier (Stage 13).

Loads the trained DeBERTa model from ml/artifacts/nlp_model/.
If the fine-tuned model artifacts are not present, raises NotImplementedError
directing the user to train the model via ml/training/train_nlp_deberta.py.
"""

from __future__ import annotations

import asyncio
from functools import lru_cache
import logging
import os
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
    """Lazy-load the DeBERTa tokenizer and classification model."""
    model_path = Path(os.getenv("NLP_FINETUNED_PATH", str(_DEFAULT_ARTIFACT_DIR)))

    has_weights = (
        (model_path / "model.safetensors").exists()
        or (model_path / "pytorch_model.bin").exists()
        or (model_path / "config.json").exists()
    )
    if not has_weights:
        return None

    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        logger.info("Loading fine-tuned DeBERTa model from %s", model_path)
        tokenizer = AutoTokenizer.from_pretrained(str(model_path))
        model = AutoModelForSequenceClassification.from_pretrained(str(model_path))
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()
        logger.info("DeBERTa threat model loaded on %s.", device)
        return tokenizer, model
    except Exception as exc:
        logger.warning("Failed to load fine-tuned DeBERTa model: %s", exc)
        return None


class FinetunedBackend(SignalBackend):
    """DeBERTa fine-tuned multi-label threat classifier."""

    @property
    def backend_name(self) -> str:
        return "finetuned"

    async def analyze(self, text: str) -> NLPSignals:
        bundle = _load_model()
        if bundle is None:
            logger.warning("FinetunedBackend model not found at %s", _DEFAULT_ARTIFACT_DIR)
            raise NotImplementedError(
                "Finetuned NLP backend is not implemented until Stage 13 fine-tuned model lands. "
                "Train the model using: python ml/training/train_nlp_deberta.py"
            )

        tokenizer, model = bundle
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._predict, tokenizer, model, text)

    def _predict(self, tokenizer: Any, model: Any, text: str) -> NLPSignals:
        import torch

        device = next(model.parameters()).device
        inputs = tokenizer(
            text,
            max_length=512,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        ).to(device)

        with torch.no_grad():
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
