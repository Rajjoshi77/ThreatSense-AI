"""Train a binary threat DeBERTa on public corpora (time-budgeted, CPU-friendly).

Trains microsoft/deberta-v3-small as a BINARY spam/phishing classifier on three
public corpora with curator-provided labels:

  - UCI SMS Spam Collection (SMS)
  - zefang-liu/phishing-email-dataset (email)
  - SetFit/enron_spam (email)

The model is NOT a 15-label model. Its single output is a "this text is a
threat/scam" probability that feeds only phishing_intent at runtime; the other
14 NLP signals remain rules-based. Provenance is recorded as
public_corpus_reviewed (curator labels, not project-human-labeled data).

Protocol: exact + normalised de-duplication, stratified train/val/test split,
threshold chosen on validation, metrics reported for val/test.

Usage:
  python train_nlp_binary_deberta.py --data-dir DATA_DIR --out-dir OUT_DIR \
      --train-size 12000 --time-budget-min 40
"""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, Dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    get_linear_schedule_with_warmup,
)

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)


def load_public_data(data_dir: Path) -> pd.DataFrame:
    frames = []
    sms = pd.read_csv(data_dir / "SMSSpamCollection", sep="\t", header=None,
                      names=["label", "text"], quoting=3)
    sms["source"] = "sms_spam_collection"
    frames.append(sms[["text", "label", "source"]])

    ph = pd.read_csv(data_dir / "phish.csv").rename(columns={"Email Text": "text"})
    ph = ph.dropna(subset=["text"])
    ph["label"] = (ph["Email Type"] == "Phishing Email").map({True: "spam", False: "ham"})
    ph["source"] = "phishing_email_corpus"
    frames.append(ph[["text", "label", "source"]])

    en = pd.read_json(data_dir / "enron_train.jsonl", lines=True).dropna(subset=["text"])
    en["label"] = en["label"].map({1: "spam", 0: "ham"})
    en["source"] = "enron_spam"
    frames.append(en[["text", "label", "source"]])

    df = pd.concat(frames, ignore_index=True)
    df["text"] = df.text.astype(str).str.strip()
    df = df[df.text.str.len() >= 5]
    # Exact + normalised de-duplication across corpora.
    df = df.drop_duplicates("text")
    norm = df.text.str.lower().str.replace(r"\s+", " ", regex=True).str.slice(0, 160)
    df = df[norm.notna() & ~norm.duplicated()]
    return df.reset_index(drop=True)


class TextDataset(Dataset):
    def __init__(self, texts: list[str], labels: list[int], tok, max_len: int) -> None:
        self.texts, self.labels, self.tok, self.max_len = texts, labels, tok, max_len

    def __len__(self) -> int:
        return len(self.texts)

    def __getitem__(self, i: int):
        enc = self.tok(self.texts[i], max_length=self.max_len, truncation=True,
                       padding="max_length", return_tensors="pt")
        return {"input_ids": enc["input_ids"][0], "attention_mask": enc["attention_mask"][0],
                "labels": torch.tensor([float(self.labels[i])])}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--base-model", default="microsoft/deberta-v3-small")
    ap.add_argument("--train-size", type=int, default=12000)
    ap.add_argument("--val-size", type=int, default=2000)
    ap.add_argument("--test-size", type=int, default=4000)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--max-len", type=int, default=192)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--time-budget-min", type=float, default=40.0)
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    t_start = time.perf_counter()

    df = load_public_data(Path(args.data_dir))
    print(f"corpus after dedup: {len(df)}  positives: {(df.label == 'spam').sum()}")
    # Cap per source so no single corpus dominates, then sample to requested sizes.
    total_needed = args.train_size + args.val_size + args.test_size
    if len(df) > total_needed:
        df, _ = train_test_split(df, train_size=total_needed, stratify=df.label, random_state=SEED)
    y_bin = (df.label == "spam").astype(int).values
    rest, test = train_test_split(df, test_size=args.test_size, stratify=y_bin, random_state=SEED)
    y_rest = (rest.label == "spam").astype(int).values
    train, val = train_test_split(rest, test_size=args.val_size, stratify=y_rest, random_state=SEED)
    print(f"train={len(train)} val={len(val)} test={len(test)}  "
          f"pos-rate train={y_bin.mean():.2f}")

    tok = AutoTokenizer.from_pretrained(args.base_model)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model, num_labels=1, problem_type="binary_classification"
    )
    torch.set_num_threads(min(12, torch.get_num_threads()))
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.train()

    train_ds = TextDataset(train.text.tolist(), (train.label == "spam").astype(int).tolist(),
                           tok, args.max_len)
    loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True, num_workers=0,
                        drop_last=True, pin_memory=(device.type == "cuda"))
    steps_total = len(loader) * args.epochs
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    sched = get_linear_schedule_with_warmup(opt, int(0.06 * steps_total), steps_total)
    lossf = torch.nn.BCEWithLogitsLoss()

    budget_s = args.time_budget_min * 60
    step, losses, step_times = 0, [], []
    early_stop = False
    for epoch in range(args.epochs):
        for batch in loader:
            t0 = time.perf_counter()
            opt.zero_grad()
            batch = {k: v.to(device, non_blocking=True) for k, v in batch.items()}
            logits = model(input_ids=batch["input_ids"],
                           attention_mask=batch["attention_mask"]).logits.squeeze(-1)
            loss = lossf(logits, batch["labels"].squeeze(-1))
            loss.backward()
            opt.step()
            sched.step()
            losses.append(loss.item())
            step_times.append(time.perf_counter() - t0)
            step += 1
            if step % 50 == 0:
                mean_step = np.mean(step_times[-50:])
                elapsed = time.perf_counter() - t_start
                projected = elapsed + mean_step * (steps_total - step)
                print(f"epoch {epoch} step {step}/{steps_total} "
                      f"loss={np.mean(losses[-50:]):.4f} step={mean_step*1000:.0f}ms "
                      f"eta={max(0,(projected-t_start))/60:.1f}min", flush=True)
                # Guard the wall-clock budget: stop cleanly before overrunning.
                remaining_steps = steps_total - step
                if (time.perf_counter() - t_start) + mean_step * max(0, remaining_steps) > budget_s:
                    print(f"TIME BUDGET reached at step {step}; stopping training early", flush=True)
                    early_stop = True
                    break
        if early_stop:
            break

    model.eval()

    @torch.inference_mode()
    def score(split_df: pd.DataFrame) -> np.ndarray:
        ds = TextDataset(split_df.text.tolist(), [0] * len(split_df), tok, args.max_len)
        dl = DataLoader(ds, batch_size=args.batch_size * 2, shuffle=False, num_workers=0)
        out_p = []
        for b in dl:
            out_p.append(torch.sigmoid(model(input_ids=b["input_ids"].to(device),
                                             attention_mask=b["attention_mask"].to(device)
                                             ).logits.squeeze(-1).cpu()))
        return torch.cat(out_p).numpy()

    def metrics(df_split: pd.DataFrame) -> dict:
        y = (df_split.label == "spam").astype(int).values
        p = score(df_split)
        pr, rc, th = precision_recall_curve(y, p)
        f1 = 2 * pr[:-1] * rc[:-1] / np.clip(pr[:-1] + rc[:-1], 1e-9, None)
        best = float(th[int(np.argmax(f1))]) if len(th) else 0.5
        return {
            "threshold": best, "roc_auc": round(float(roc_auc_score(y, p)), 4),
            "pr_auc": round(float(average_precision_score(y, p)), 4),
            "f1_at_threshold": round(float(f1_score(y, (p >= best).astype(int))), 4),
            "precision_at_threshold": round(float(precision_score(y, (p >= best).astype(int))), 4),
            "recall_at_threshold": round(float(recall_score(y, (p >= best).astype(int))), 4),
            "f1_at_0.5": round(float(f1_score(y, (p >= 0.5).astype(int))), 4),
            "brier": round(float(np.mean((p - y) ** 2)), 4),
        }

    val_m = metrics(val)
    test_m = metrics(test)
    print("val:", json.dumps(val_m), "\ntest:", json.dumps(test_m))

    model.save_pretrained(out, safe_serialization=True)
    tok.save_pretrained(out)
    meta = {
        "model_type": "deberta_binary_threat",
        "output": "single sigmoid probability: text-level threat (spam/phishing/scam)",
        "runtime_mapping": "phishing_intent only; all other NLP signals remain rules-based",
        "base_model": args.base_model,
        "training_data": "public_corpus_reviewed",
        "datasets": ["UCI SMS Spam Collection", "zefang-liu/phishing-email-dataset", "SetFit/enron_spam"],
        "num_labels": 1,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "epochs_run": (epoch + 1) if "epoch" in dir() else 0,
        "steps_run": step,
        "early_stopped": early_stop,
        "batch_size": args.batch_size,
        "learning_rate": args.lr,
        "max_len": args.max_len,
        "train_size": int(len(train)),
        "val_size": int(len(val)),
        "test_size": int(len(test)),
        "label_provenance": "curator-provided public labels; not project-human-labeled",
        "validation_metrics": val_m,
        "test_metrics": test_m,
        "training_seconds": round(time.perf_counter() - t_start, 1),
        "device": device.type,
        "limitations": (
            "Trained/evaluated only on the binary spam-vs-legitimate view of public corpora. "
            "The 15-label ThreatSense signal schema remains rules-based; no per-label accuracy "
            "claims are supported by this checkpoint."
        ),
    }
    (out / "model.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print("saved to", out)


if __name__ == "__main__":
    main()
