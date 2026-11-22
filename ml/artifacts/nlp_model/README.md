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
cp ml/data/gold_labels_template.csv ml/data/gold_labels.csv
# Fill gold_labels.csv with at least 50 human-reviewed examples, then:
pip install -r ml/training/requirements.txt
python ml/training/train_nlp_deberta.py --epochs 4
```

That writes model weights, `config.json`, tokenizer files and `model.meta.json`
into this directory. Normal checkpoints identify `training_data` as
`human_labeled`; local checkpoints without readable provenance or with any other
provenance are deliberately rejected. If a compatible checkpoint is unavailable
or inference fails, the API logs a warning and continues with the rules backend.
Analysis responses identify the backend actually used.

For deployment without copying a large checkpoint into the application image,
host the complete trained checkpoint in a Hugging Face repository and set
`NLP_FINETUNED_PATH=owner/model-repository`. For private repositories, also set
`HF_TOKEN` as a secret. Keep `NLP_BACKEND=finetuned`; the API verifies the
checkpoint's 15-label configuration and label order when it starts. If loading
fails, it continues with rules until the checkpoint is fixed and the API restarted.

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

## Use the fine-tuned backend

Local checkpoint:

```bash
# Set from the backend working directory before starting Uvicorn
NLP_BACKEND=finetuned
NLP_FINETUNED_PATH=/absolute/path/to/nlp_model
```

Hugging Face Hub checkpoint:

```bash
NLP_BACKEND=finetuned
NLP_FINETUNED_PATH=owner/model-repository
HF_TOKEN=your-private-token-if-required
```

Use a model trained with this project's `SIGNAL_LABELS` order and human-reviewed
examples with verified provenance. The serving backend checks for provenance,
15 outputs, and matching labels. Hub repositories must include `model.meta.json`
with `training_data: human_labeled`. Do not commit access tokens or large model
weights to Git.

## Environment notes

- Train with a stack that was validated together: `torch` 2.7.x + `transformers` 4.x.
  `transformers` 5.x produced **NaN loss** with `torch` 2.15 in testing; the trainer
  now aborts on non-finite loss instead of silently writing a broken model.
- The DeBERTa-v3 fast tokenizer needs `protobuf >= 7.36.1` for `sentencepiece` 0.2.x,
  which breaks Streamlit. The trainer therefore falls back to the slow SentencePiece
  tokenizer, so `protobuf < 7` works fine.
- The committed metadata records a historical synthetic bootstrap run; it is not a
  production checkpoint. Normal training now requires at least 50 human-labeled rows
  in `ml/data/gold_labels.csv`. The optional `--small` mode is only a synthetic smoke
  test and requires a separate `--out` directory.
