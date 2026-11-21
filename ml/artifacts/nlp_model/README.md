# DeBERTa NLP Model Artifacts

Fine-tuned multi-label classifier for the 15 `NLPSignals` consumed by the NLP engine.

| Item | Value |
|---|---|
| Base model | `microsoft/deberta-v3-small` |
| Task | 15-signal multi-label threat classification |
| Head | `BCEWithLogitsLoss` + `sigmoid`, `problem_type=multi_label_classification` |
| Trained on | synthetic bootstrap set (48 labelled examples) |
| Epochs | 4 |
| Avg loss | 0.6495 → 0.4411 → 0.4008 → **0.3721** |
| Device | CPU (torch 2.7.1) |
| Serve with | `NLP_BACKEND=finetuned` |

## Signals

`urgency`, `fear`, `authority`, `reward_scarcity`, `financial_intent`,
`credential_request`, `manipulation`, `phishing_intent`, `scam_intent`,
`investment_context`, `recruitment_context`, `tech_support_context`,
`government_service_claim`, `payment_request`, `remote_access_request`

## The weights are not in git

`model.safetensors` is ~542 MB, above GitHub's 100 MB per-file limit, so
`ml/artifacts/**/*.safetensors` is gitignored. Regenerate the weights locally:

```powershell
# from the repository root
pip install -r ml/training/requirements.txt
python ml/training/train_nlp_deberta.py --epochs 4
```

That writes `model.safetensors`, `config.json`, the tokenizer files and
`model.meta.json` into this directory. Until the weights exist,
`FinetunedBackend` raises `NotImplementedError` telling you to run the script —
`NLP_BACKEND=rules` keeps working meanwhile.

If you do need the weights in the repo, use Git LFS:

```powershell
git lfs install
git lfs track "ml/artifacts/**/*.safetensors"
git add .gitattributes
```

## Committed alongside the weights' metadata

- `config.json` — architecture + `id2label`/`label2id` mapping for the 15 signals
- `model.meta.json` — base model, epochs, lr, device, training time
- `REPORT.md` — human-readable training report (regenerated on every run)

## Environment notes

- Train with a stack that was validated together: `torch` 2.7.x + `transformers` 4.x.
  `transformers` 5.x produced **NaN loss** with `torch` 2.15 in testing; the trainer
  now aborts on non-finite loss instead of silently writing a broken model.
- The DeBERTa-v3 fast tokenizer needs `protobuf >= 7.36.1` for `sentencepiece` 0.2.x,
  which breaks Streamlit. The trainer therefore falls back to the slow SentencePiece
  tokenizer, so `protobuf < 7` works fine.
- Accuracy is limited by the synthetic bootstrap set. Fill
  `ml/data/gold_labels_template.csv` with real labelled samples and retrain to get a
  production-grade classifier.
