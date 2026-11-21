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
import math
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

# Suppress noisy external library logs (HTTP requests, downloads, etc.)
for noisy in ("urllib3", "httpx", "httpcore", "huggingface_hub", "transformers"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

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
        {
            "text": "Your parcel is held at customs. Pay the $2.99 clearance fee via this link within 24 hours or it will be returned.",
            "labels": {
                "urgency": 0.9, "payment_request": 0.9, "phishing_intent": 0.8, "manipulation": 0.6
            }
        },
        {
            "text": "Final notice: your electricity will be disconnected today. Call our billing line and settle the overdue amount by card.",
            "labels": {
                "urgency": 1.0, "fear": 0.9, "authority": 0.8, "government_service_claim": 0.7, "payment_request": 0.9
            }
        },
        {
            "text": "This is the IRS. A warrant has been issued for your arrest for unpaid taxes. Press 1 to speak with the officer.",
            "labels": {
                "authority": 1.0, "government_service_claim": 1.0, "fear": 1.0, "urgency": 0.9, "scam_intent": 1.0
            }
        },
        {
            "text": "Your Netflix payment failed. Update your card details here to avoid service interruption.",
            "labels": {
                "phishing_intent": 1.0, "credential_request": 0.8, "payment_request": 0.8, "urgency": 0.7, "fear": 0.4
            }
        },
        {
            "text": "Security alert: unusual sign-in from a new device. Confirm it was you by entering your email password.",
            "labels": {
                "fear": 0.8, "credential_request": 1.0, "phishing_intent": 1.0, "urgency": 0.6
            }
        },
        {
            "text": "DM me on Telegram to join the trading signals group. Members made 40% profit last week. Limited slots!",
            "labels": {
                "investment_context": 1.0, "reward_scarcity": 0.9, "scam_intent": 0.9, "financial_intent": 0.8, "manipulation": 0.7
            }
        },
        {
            "text": "Earn from home: no experience needed, flexible hours. Just pay the $99 starter kit fee to begin today.",
            "labels": {
                "recruitment_context": 1.0, "financial_intent": 0.8, "payment_request": 0.8, "scam_intent": 0.9
            }
        },
        {
            "text": "Congratulations! Your phone number was selected in our annual draw. Claim your iPhone 15 before midnight.",
            "labels": {
                "reward_scarcity": 1.0, "urgency": 0.8, "scam_intent": 1.0, "manipulation": 0.7
            }
        },
        {
            "text": "I am the CFO. I need you to buy 5 gift cards for client appreciation and send me the codes ASAP. Keep this confidential.",
            "labels": {
                "authority": 0.9, "urgency": 0.9, "payment_request": 1.0, "manipulation": 0.9, "scam_intent": 0.9
            }
        },
        {
            "text": "Your computer is infected with 14 viruses. Download our free antivirus tool now to clean your PC.",
            "labels": {
                "fear": 1.0, "tech_support_context": 1.0, "urgency": 0.8, "manipulation": 0.8, "scam_intent": 0.7
            }
        },
        {
            "text": "Microsoft support here: we detected malicious activity. Install this remote desktop app so a technician can access your machine.",
            "labels": {
                "tech_support_context": 1.0, "remote_access_request": 1.0, "authority": 0.9, "fear": 0.8, "phishing_intent": 0.8
            }
        },
        {
            "text": "Bank notice: your account will be frozen due to suspicious transactions. Verify your identity with your card PIN immediately.",
            "labels": {
                "fear": 1.0, "urgency": 1.0, "credential_request": 1.0, "phishing_intent": 1.0, "authority": 0.7
            }
        },
        {
            "text": "You have been chosen for a research panel. Complete the 2-minute survey and receive a $100 gift voucher.",
            "labels": {
                "reward_scarcity": 0.8, "scam_intent": 0.6, "manipulation": 0.5
            }
        },
        {
            "text": "Donate to the earthquake relief fund through our verified crypto wallet. Every satoshi counts. Act now.",
            "labels": {
                "payment_request": 0.9, "urgency": 0.8, "manipulation": 0.8, "financial_intent": 0.7, "scam_intent": 0.8
            }
        },
        {
            "text": "Romantic message: I can't wait to see you. My flight is booked but I'm stuck at customs and need $800 for the ticket fee. Wire it today please.",
            "labels": {
                "payment_request": 1.0, "urgency": 0.9, "manipulation": 0.9, "scam_intent": 1.0, "financial_intent": 0.8
            }
        },
        {
            "text": "Job offer from Silicon Valley startup: $180k/year, remote. Send your bank account number for the onboarding payroll setup.",
            "labels": {
                "recruitment_context": 1.0, "credential_request": 0.9, "reward_scarcity": 0.9, "phishing_intent": 0.9, "scam_intent": 1.0
            }
        },
        {
            "text": "MFA code request detected. If this wasn't you, share the 6-digit code we just texted you so support can block the attacker.",
            "labels": {
                "credential_request": 1.0, "phishing_intent": 1.0, "fear": 0.7, "urgency": 0.8
            }
        },
        {
            "text": "Exclusive presale access: invest before the token listing and lock in 5x apy. Doors close in 3 hours.",
            "labels": {
                "investment_context": 1.0, "reward_scarcity": 1.0, "urgency": 0.9, "financial_intent": 0.9, "scam_intent": 0.8
            }
        },
        {
            "text": "This is agent Johnson from Windows technical department. Your license expired and the system is at risk. Allow remote connection to renew it.",
            "labels": {
                "authority": 1.0, "tech_support_context": 1.0, "remote_access_request": 1.0, "fear": 0.9, "urgency": 0.8
            }
        },
        {
            "text": "Your KYC documents expired. Re-upload your ID and selfie on our portal to keep trading. Visit the secure link now.",
            "labels": {
                "urgency": 0.8, "credential_request": 0.9, "government_service_claim": 0.5, "phishing_intent": 0.8, "manipulation": 0.5
            }
        },
        {
            "text": "The court has scheduled a hearing regarding the case filed against your SSN. Confirm your details with the clerk to avoid a default judgment.",
            "labels": {
                "authority": 1.0, "government_service_claim": 1.0, "fear": 1.0, "urgency": 0.9, "credential_request": 0.7
            }
        },
        {
            "text": "Send 0.05 BTC to the wallet below within 48 hours or all your files will be encrypted and leaked.",
            "labels": {
                "fear": 1.0, "urgency": 1.0, "payment_request": 1.0, "manipulation": 1.0, "scam_intent": 1.0
            }
        },
        {
            "text": "You've earned 8,500 loyalty points which expire tonight. Redeem them now by confirming your account login.",
            "labels": {
                "reward_scarcity": 1.0, "urgency": 1.0, "credential_request": 0.9, "phishing_intent": 0.8
            }
        },
        {
            "text": "Local charity 5k run this Saturday — registration is free and open to everyone. See the community board for details.",
            "labels": {}
        },
        {
            "text": "Reminder: the team retrospective is moved to Thursday 10am. Agenda and notes are in the shared drive.",
            "labels": {}
        },
        {
            "text": "Your order #48291 has shipped and will arrive Tuesday. Track it from your account page when convenient.",
            "labels": {}
        },
        {
            "text": "Happy birthday! The crew is planning dinner on Friday, let us know which place you prefer.",
            "labels": {}
        },
        {
            "text": "The library book you reserved is ready for pickup at the front desk until Sunday.",
            "labels": {}
        },
        {
            "text": "Our meeting notes from today: launch date confirmed for March 3, budget approved, next sync on Monday.",
            "labels": {}
        },
        {
            "text": "Attached are the revised project requirements. Please review section 4 before the client call.",
            "labels": {}
        },
        {
            "text": "Your monthly statement is now available in online banking. No action is required.",
            "labels": {}
        },
        {
            "text": "Registration for the spring marathon closes next month; early-bird pricing applies until then.",
            "labels": {}
        },
        {
            "text": "The dentist confirmed your cleaning appointment for Wednesday at 3pm. Reply to reschedule if needed.",
            "labels": {}
        },
        {
            "text": "Thank you for contacting support. Your ticket #10543 has been resolved. Reply if you need further help.",
            "labels": {}
        },
        {
            "text": "School notice: parent-teacher conferences run next week; sign-up sheets are posted in the lobby.",
            "labels": {}
        },
        {
            "text": "Welcome to the course! Module 1 covers Python basics; exercises are due at the end of the week.",
            "labels": {}
        },
        {
            "text": "Flight reminder: check-in for tomorrow's trip opens 24 hours before departure in the airline app.",
            "labels": {}
        },
        {
            "text": "The hoa meeting minutes from April are attached for your review along with the treasurer's report.",
            "labels": {}
        },
        {
            "text": "Conference talk accepted! We'll need your slide deck two weeks before the event.",
            "labels": {}
        },
        {
            "text": "Your subscription renews on the 15th at the same rate; you can manage billing any time in settings.",
            "labels": {}
        },
        {
            "text": "The weather service issued a flood watch for low-lying areas through Saturday evening.",
            "labels": {}
        },
        {
            "text": "Great catching up at the reunion! Send photos whenever you get a chance.",
            "labels": {}
        },
        {
            "text": "The pharmacy confirms your prescription refill is ready; pick it up at the counter during store hours.",
            "labels": {}
        },
    ]


def _tfm_version() -> str:
    """Return the installed transformers version string (for diagnostics)."""
    try:
        import transformers

        return transformers.__version__
    except Exception:  # pragma: no cover - transformers is a hard requirement
        return "unknown"


def _load_tokenizer(model_name: str):
    """Load the DeBERTa-v3 tokenizer, tolerating a protobuf-constrained environment.

    The *fast* DeBERTa-v3 tokenizer converts the SentencePiece model via
    ``sentencepiece_model_pb2``, whose generated code requires a protobuf runtime
    >= the gencode version (7.36.1 for sentencepiece 0.2.x). Environments that must
    keep ``protobuf<7`` (Streamlit, google-api-core, grpcio-status) cannot use it.

    The *slow* tokenizer only needs ``sentencepiece`` itself, so we fall back to it.
    Both produce identical token ids for DeBERTa-v3, so training results are the same.
    """
    from transformers import AutoTokenizer

    try:
        return AutoTokenizer.from_pretrained(model_name, use_fast=True)
    except ImportError:
        raise
    except Exception as fast_err:
        logger.warning(
            "Fast tokenizer unavailable (%s). Falling back to the slow SentencePiece "
            "tokenizer, which needs only 'sentencepiece' and no protobuf upgrade.",
            fast_err,
        )
        try:
            tok = AutoTokenizer.from_pretrained(model_name, use_fast=False)
        except ImportError as e:
            logger.error(
                "Failed to load the DeBERTa-v3 tokenizer: %s\n"
                "The tokenizer requires 'sentencepiece' (and a compatible 'protobuf' runtime).\n"
                "Fix:  pip install -r ml/training/requirements.txt\n"
                "      or:  pip install sentencepiece sentencepiece==0.1.99 'protobuf<7'",
                e,
            )
            raise
        logger.info("Using slow tokenizer %s (no protobuf dependency).", type(tok).__name__)
        return tok


def train(
    base_model_name: str = "microsoft/deberta-v3-small",
    epochs: int = 3,
    batch_size: int = 8,
    lr: float = 2e-5,
    small: bool = False,
    out_dir: Path | str | None = None,
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
        # Expand for a few training iterations so the tokenizer sees enough steps
        data_items = synthetic * (3 if small else 6)

    logger.info("Loaded %d training examples", len(data_items))

    # 2. Tokenizer & Model
    tokenizer = _load_tokenizer(base_model_name)
    num_labels = len(SIGNAL_LABELS)

    model = AutoModelForSequenceClassification.from_pretrained(
        base_model_name,
        num_labels=num_labels,
        problem_type="multi_label_classification",
        id2label={i: name for i, name in enumerate(SIGNAL_LABELS)},
        label2id={name: i for i, name in enumerate(SIGNAL_LABELS)},
        use_safetensors=False,
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

            if not math.isfinite(loss.item()):
                raise RuntimeError(
                    f"Non-finite loss ({loss.item()}) at epoch {epoch} step {step}. "
                    "Training cannot recover from this. This is almost always an "
                    "incompatible torch/transformers combination (e.g. transformers 5.x "
                    "with a torch build it was not validated against). "
                    "Use the pinned stack: pip install -r ml/training/requirements.txt "
                    f"(currently torch {torch.__version__}, transformers {_tfm_version()})."
                )

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
    artifact_dir = Path(out_dir) if out_dir else ARTIFACT_DIR
    artifact_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Saving fine-tuned model and tokenizer to %s", artifact_dir)
    model.save_pretrained(artifact_dir)
    tokenizer.save_pretrained(artifact_dir)

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

    with open(artifact_dir / "model.meta.json", "w", encoding="utf-8") as f:
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
    with open(artifact_dir / "REPORT.md", "w", encoding="utf-8") as f:
        f.write(report_md)

    logger.info("DeBERTa artifacts saved successfully. Ready for inference!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train DeBERTa multi-label threat model")
    parser.add_argument("--small", action="store_true", help="Use small synthetic dataset for testing")
    parser.add_argument("--base-model", default="microsoft/deberta-v3-small", help="Base HuggingFace DeBERTa model")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=8, help="Batch size")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate")
    parser.add_argument(
        "--out",
        default=None,
        help="Output directory for artifacts (default: ml/artifacts/nlp_model). "
        "Use a separate dir for smoke tests so the production model is not overwritten.",
    )
    args = parser.parse_args()

    train(
        base_model_name=args.base_model,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        small=args.small,
        out_dir=args.out,
    )
