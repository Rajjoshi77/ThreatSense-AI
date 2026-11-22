"""Independent evaluation of the ThreatSense DeBERTa checkpoint on public corpora.

The checkpoint is NOT retrained or tuned here. Public corpora provide a single
binary label (spam/phishing vs. legitimate), so only the binary
"threat vs. benign" view is evaluated, using score = max(phishing_intent,
scam_intent). The other 13 labels cannot be evaluated without reviewed labels.

Protocol: de-duplicate -> stratified sample -> 50% validation / 50% test per
dataset -> threshold chosen on validation only -> frozen -> test metrics with
bootstrap 95% CIs. The rules backend is scored with the same protocol.

Usage: python evaluate_nlp_public.py DATA_DIR OUT_DIR
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split

SEED = 42
ROOT = Path(__file__).resolve().parents[2]
CKPT = ROOT / "ml" / "artifacts" / "nlp_model"
SAMPLE = {"sms_spam": 3000, "phishing_email": 2000, "enron_spam": 2000}
LABELS = [
    "urgency", "fear", "authority", "reward_scarcity", "financial_intent",
    "credential_request", "manipulation", "phishing_intent", "scam_intent",
    "investment_context", "recruitment_context", "tech_support_context",
    "government_service_claim", "payment_request", "remote_access_request",
]


def load_datasets(data: Path) -> dict[str, pd.DataFrame]:
    sms = pd.read_csv(data / "SMSSpamCollection", sep="\t", header=None,
                      names=["l", "text"], quoting=3)
    sms["y"] = (sms.l == "spam").astype(int)
    ph = pd.read_csv(data / "phish.csv").rename(columns={"Email Text": "text"})
    ph = ph.dropna(subset=["text"])
    ph["y"] = (ph["Email Type"] == "Phishing Email").astype(int)
    en = pd.read_json(data / "enron_train.jsonl", lines=True).dropna(subset=["text"])
    en["y"] = en["label"].astype(int)
    out = {}
    for name, df in {"sms_spam": sms, "phishing_email": ph, "enron_spam": en}.items():
        df = df[["text", "y"]].copy()
        df["text"] = df.text.astype(str).str.strip()
        df = df[df.text.str.len() >= 5].drop_duplicates("text")
        n = min(SAMPLE[name], len(df))
        df, _ = train_test_split(df, train_size=n, stratify=df.y, random_state=SEED)
        out[name] = df.reset_index(drop=True)
    return out


def deberta_scores(texts: list[str], batch: int = 16) -> tuple[np.ndarray, list[float]]:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(CKPT, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(CKPT, local_files_only=True).eval()
    ids = {LABELS[i]: i for i in range(len(LABELS))}
    assert [model.config.id2label[i] for i in range(len(LABELS))] == LABELS
    order = np.argsort([len(t) for t in texts])
    probs = np.zeros((len(texts), len(LABELS)), dtype=np.float32)
    lat = []
    torch.set_num_threads(min(8, torch.get_num_threads()))
    for s in range(0, len(texts), batch):
        idx = order[s:s + batch]
        t0 = time.perf_counter()
        enc = tok([texts[i] for i in idx], max_length=256, truncation=True,
                  padding=True, return_tensors="pt")
        with torch.inference_mode():
            p = torch.sigmoid(model(**enc).logits).numpy()
        lat.append((time.perf_counter() - t0) * 1000 / len(idx))
        probs[idx] = p
        if (s // batch) % 50 == 0:
            print(f"  deberta {s}/{len(texts)}", flush=True)
    return np.maximum(probs[:, ids["phishing_intent"]], probs[:, ids["scam_intent"]]), lat


def rules_scores(texts: list[str]) -> np.ndarray:
    sys.path.insert(0, str(ROOT / "backend"))
    from app.engines.nlp.backends.rules import RulesBackend

    be = RulesBackend()

    async def run():
        res = [await be.analyze(t) for t in texts]
        return np.array([max(r.phishing_intent, r.scam_intent) for r in res])

    return asyncio.run(run())


def ece(y, p, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    total, e = len(y), 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & ((p < hi) if hi < 1 else (p <= hi))
        if m.any():
            e += m.sum() / total * abs(y[m].mean() - p[m].mean())
    return float(e)


def pick_threshold(y, s):
    pr, rc, th = precision_recall_curve(y, s)
    f1 = 2 * pr[:-1] * rc[:-1] / np.clip(pr[:-1] + rc[:-1], 1e-9, None)
    return float(th[int(np.argmax(f1))]) if len(th) else 0.5


def metrics(y, s, thr):
    pred = (s >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    fpr_curve, tpr_curve, _ = roc_curve(y, s)
    return {
        "threshold": thr, "n": int(len(y)), "positives": int(y.sum()),
        "accuracy": accuracy_score(y, pred), "balanced_accuracy": balanced_accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "specificity": tn / (tn + fp) if tn + fp else float("nan"),
        "f1": f1_score(y, pred, zero_division=0), "mcc": matthews_corrcoef(y, pred),
        "fpr": fp / (fp + tn) if fp + tn else float("nan"),
        "fnr": fn / (fn + tp) if fn + tp else float("nan"),
        "roc_auc": roc_auc_score(y, s), "pr_auc": average_precision_score(y, s),
        "recall_at_1pct_fpr": float(np.max(tpr_curve[fpr_curve <= 0.01])),
        "brier": brier_score_loss(y, s), "ece": ece(y, s),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def bootstrap_ci(y, s, thr, n=1000):
    rng = np.random.default_rng(SEED)
    keys = ["accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "mcc"]
    acc = {k: [] for k in keys}
    for _ in range(n):
        i = rng.integers(0, len(y), len(y))
        if y[i].min() == y[i].max():
            continue
        m = metrics(y[i], s[i], thr)
        for k in keys:
            acc[k].append(m[k])
    return {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] for k, v in acc.items()}


def main(data_dir: str, out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ds = load_datasets(Path(data_dir))
    results: dict = {"protocol": __doc__.split("\n\n")[1], "models": {}, "datasets": {}}
    splits = {}
    for name, df in ds.items():
        val, test = train_test_split(df, test_size=0.5, stratify=df.y, random_state=SEED)
        splits[name] = (val.reset_index(drop=True), test.reset_index(drop=True))
        results["datasets"][name] = {"validation": len(val), "test": len(test),
                                     "test_positive_rate": float(test.y.mean())}

    all_texts = [t for n in splits for part in splits[n] for t in part.text]
    t0 = time.perf_counter()
    d_all, lat = deberta_scores(all_texts)
    r_all = rules_scores(all_texts)
    print("scored", len(all_texts), "texts in", round(time.perf_counter() - t0), "s")
    results["latency_ms_per_text_batch16"] = {
        "p50": float(np.percentile(lat, 50)), "p95": float(np.percentile(lat, 95)),
        "mean": float(np.mean(lat))}

    pos = 0
    for name in splits:
        val, test = splits[name]
        nv, nt = len(val), len(test)
        for mname, allsc in (("deberta_checkpoint", d_all), ("rules_baseline", r_all)):
            sv, st = allsc[pos:pos + nv], allsc[pos + nv:pos + nv + nt]
            thr = pick_threshold(val.y.values, sv)
            m = metrics(test.y.values, st, thr)
            m["ci95"] = bootstrap_ci(test.y.values, st, thr)
            m["fixed_threshold_0.5"] = {k: v for k, v in metrics(test.y.values, st, 0.5).items()
                                        if k in ("precision", "recall", "f1", "fpr", "accuracy")}
            results["models"].setdefault(mname, {})[name] = m
        pos += nv + nt
    (out / "nlp_public_eval.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps({m: {d: {k: round(v, 3) for k, v in r.items()
                              if k in ("precision", "recall", "f1", "roc_auc", "pr_auc", "fpr")}
                          for d, r in v.items()} for m, v in results["models"].items()}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
