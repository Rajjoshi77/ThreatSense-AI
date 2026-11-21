#!/usr/bin/env python3
"""
Train DeBERTa multi-label threat classifier for ThreatSense AI (Stage 13).

Usage:
    python ml/training/train_nlp_deberta.py [--small] [--base-model MODEL_NAME] [--epochs N]

Options:
    --small         Train on a synthetic dataset (100 examples) for fast testing/CI.
    --base-model    Pretrained model (default: microsoft/deberta-v3-small).
                    Alternative: microsoft/deberta-v3-base
    --epochs        Number of training epochs (default: 3).
    --batch-size    Training batch size (default: 8).
    --lr            Learning rate (default: 2e-5).

Outputs:
    ml/artifacts/nlp_model/pytorch_model.bin (or safetensors)
    ml/artifacts/nlp_model/config.json
    ml/artifacts/nlp_model/tokenizer files
    ml/artifacts/nlp_model/model.meta.json
    ml/artifacts/nlp_model/REPORT.md

Run from repository root.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Setup paths
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

ARTIFACT_DIR = ROOT / "ml" / "artifacts" / "nlp_model"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# The 15 multi-label threat signals matching NLPSignals in schemas.py
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


def _make_synthetic_dataset() -> list[dict]:
    """Generate small representative multi-label examples for testing."""
    return [
        {
            "text": "URGENT: Your account has been suspended. Click here to verify your password and OTP immediately.",
            "labels": {
                "urgency": 1.0, "fear": 0.8, "credential_request": 1.0, "phishing_intent": 1.0, "manipulation": 0.7
            }
        },
        {
            "text": "Congratulations! You won $1,000,000 in our international lottery! Send $150 processing fee via wire transfer.",
            "labels": {
                "reward_scarcity": 1.0, "financial_intent": 0.9, "scam_intent": 1.0, "payment_request": 0.9
            }
        },
        {
            "text": "Official notice from the Income Tax Department. Outstanding penalty detected. Pay immediately to avoid legal action.",
            "labels": {
                "authority": 1.0, "government_service_claim": 1.0, "fear": 0.9, "urgency": 0.8, "payment_request": 0.8
            }
        },
        {
            "text": "WARNING: Trojan detected on Windows. Contact Microsoft support. Download AnyDesk for remote cleanup.",
            "labels": {
                "tech_support_context": 1.0, "remote_access_request": 1.0, "fear": 0.8, "manipulation": 0.7
            }
        },
        {
            "text": "Work from home job offer. Earn $500 daily with zero experience. Register now by paying $50 security deposit.",
            "labels": {
                "recruitment_context": 1.0, "reward_scarcity": 0.7, "financial_intent": 0.8, "scam_intent": 0.9
            }
        },
        {
            "text": "Hi Bob, please review the attached quarterly slide deck before our 2pm sync. Best, Sarah.",
            "labels": {}
        },
        {
            "text": "Weekly newsletter: Tech trends in artificial intelligence, cloud architectures, and cybersecurity updates.",
            "labels": {}
        },
        {
            "text": "Guaranteed 300% returns in 7 days on crypto arbitrage trading platform. Invest your bitcoin now.",
            "labels": {
                "investment_context": 1.0, "financial_intent": 0.9, "reward_scarcity": 0.8, "scam_intent": 0.9
            }
        },
    ]


def train(
    base_model_name: str = "microsoft/deberta-v3-small",
    epochs: int = 3,
    batch_size: int = 8,
    lr: float = 2e-5,
    small: bool = False,
):
    """Fine-tune DeBERTa model on multi-label threat dataset."""
    logger.info("Initializing DeBERTa training pipeline...")
    logger.info("Base model: %s | Epochs: %d | Batch size: %d | LR: %e", base_model_name, epochs, batch_size, lr)

    try:
        import torch
        from torch.utils.data import DataLoader, Dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            get_linear_schedule_with_warmup,
        )
    except ImportError as e:
        logger.error(
            "Missing PyTorch or HuggingFace Transformers. Install via:\n"
            "    pip install torch transformers datasets accelerate"
        )
        sys.exit(1)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info("Using device: %s", device)

    # 1. Dataset Preparation
    data_items = []
    gold_csv = ROOT / "ml" / "data" / "gold_labels_template.csv"
    if not small and gold_csv.exists() and gold_csv.stat().st_size > 1000:
        import csv
        logger.info("Loading ground truth dataset from %s", gold_csv)
        with open(gold_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                text = row.get("text", "").strip()
                if not text:
                    continue
                labels = {}
                for signal in SIGNAL_LABELS:
                    col = f"label_{signal}"
                    val = float(row.get(col, 0.0) or 0.0)
                    if val > 0:
                        labels[signal] = val
                data_items.append({"text": text, "labels": labels})
    else:
        logger.info("Using representative synthetic dataset (%s mode)", "small" if small else "fallback")
        synthetic = _make_synthetic_dataset()
        # Expand for a few training iterations if in small mode
        data_items = synthetic * (10 if small else 25)

    logger.info("Loaded %d training examples", len(data_items))

    # 2. Tokenizer & Model
    tokenizer = AutoTokenizer.from_pretrained(base_model_name)
    num_labels = len(SIGNAL_LABELS)

    model = AutoModelForSequenceClassification.from_pretrained(
        base_model_name,
        num_labels=num_labels,
        problem_type="multi_label_classification",
        id2label={i: name for i, name in enumerate(SIGNAL_LABELS)},
        label2id={name: i for i, name in enumerate(SIGNAL_LABELS)},
    )
    model.to(device)

    # 3. PyTorch Dataset
    max_len = 128 if small else 256
    class ThreatDataset(Dataset):
        def __init__(self, items, tok, max_len=max_len):
            self.items = items
            self.tok = tok
            self.max_len = max_len

        def __len__(self):
            return len(self.items)

        def __getitem__(self, idx):
            item = self.items[idx]
            enc = self.tok(
                item["text"],
                max_length=self.max_len,
                padding="max_length",
                truncation=True,
                return_tensors="pt",
            )
            target = torch.zeros(num_labels, dtype=torch.float)
            for sig, val in item["labels"].items():
                if sig in SIGNAL_LABELS:
                    target[SIGNAL_LABELS.index(sig)] = float(val)

            return {
                "input_ids": enc["input_ids"].squeeze(0),
                "attention_mask": enc["attention_mask"].squeeze(0),
                "labels": target,
            }

    dataset = ThreatDataset(data_items, tokenizer, max_len=max_len)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    total_steps = len(loader) * epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=int(total_steps * 0.1), num_training_steps=total_steps)
    criterion = torch.nn.BCEWithLogitsLoss()

    # 4. Training Loop
    logger.info("Starting training loop (%d epochs, %d batches per epoch, max_len=%d)...", epochs, len(loader), max_len)
    start_time = time.time()
    model.train()

    for epoch in range(1, epochs + 1):
        total_loss = 0.0
        for step, batch in enumerate(loader, 1):
            optimizer.zero_grad()
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            loss = criterion(logits, labels)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()

            total_loss += loss.item()
            logger.info("  [Epoch %d/%d] Batch %d/%d — Batch Loss: %.4f", epoch, epochs, step, len(loader), loss.item())

        avg_loss = total_loss / len(loader)
        logger.info("Epoch %d/%d Complete — Average Loss: %.4f", epoch, epochs, avg_loss)

    elapsed = time.time() - start_time
    logger.info("Training completed in %.1f seconds", elapsed)

    # 5. Save Artifacts
    logger.info("Saving fine-tuned model and tokenizer to %s", ARTIFACT_DIR)
    model.save_pretrained(ARTIFACT_DIR)
    tokenizer.save_pretrained(ARTIFACT_DIR)

    # Metadata & Report
    meta = {
        "model_type": "deberta_multilabel_threat",
        "base_model": base_model_name,
        "num_labels": num_labels,
        "labels": SIGNAL_LABELS,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "epochs": epochs,
        "batch_size": batch_size,
        "learning_rate": lr,
        "training_seconds": round(elapsed, 2),
        "device": str(device),
    }

    with open(ARTIFACT_DIR / "model.meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    report_md = f"""# DeBERTa Threat Model Training Report

- **Base Model:** `{base_model_name}`
- **Task:** 15-Signal Multi-Label Cyber Threat Classification
- **Trained At:** {meta['trained_at']}
- **Training Time:** {elapsed:.1f}s ({meta['device']})
- **Signals Output:**
{chr(10).join(f'  - `{s}`' for s in SIGNAL_LABELS)}

## Production Usage
Set `NLP_BACKEND=finetuned` in your `.env` file to activate this model in ThreatSense AI.
"""
    with open(ARTIFACT_DIR / "REPORT.md", "w", encoding="utf-8") as f:
        f.write(report_md)

    logger.info("DeBERTa artifacts saved successfully. Ready for inference!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train DeBERTa multi-label threat model")
    parser.add_argument("--small", action="store_true", help="Use small synthetic dataset for testing")
    parser.add_argument("--base-model", default="microsoft/deberta-v3-small", help="Base HuggingFace DeBERTa model")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=8, help="Batch size")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate")
    args = parser.parse_args()

    train(
        base_model_name=args.base_model,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        small=args.small,
    )
