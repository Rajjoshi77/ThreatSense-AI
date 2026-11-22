// ── Evaluation data sources ────────────────────────────────────────────────────
// NLP metrics come from ml/evaluation/results/nlp_public_eval.json, produced by
// ml/evaluation/evaluate_nlp_public.py (frozen thresholds, bootstrap 95% CIs).
// URL model metrics come from ml/artifacts/url_model/REPORT.md (model card).

import nlpEval from './nlp_public_eval.json'

export const NLP_EVAL = nlpEval

// URL XGBoost model card (synthetic CI provenance — metrics shown for completeness).
export const URL_MODEL = {
  name: 'URL XGBoost (Calibrated)',
  version: '20260929_142658',
  type: 'XGBoost + Platt scaling · 28 URL structural features',
  status: 'synthetic-ci',
  statusLabel: 'Synthetic CI Only',
  statusDetail:
    'Trained on 100 synthetic/fixture URLs for pipeline testing. The backend skips this model; it uses structural fallback scoring until a model with reviewed production provenance is evaluated.',
  testSet: { train: 80, test: 21, positiveRatio: 0.5 },
  latency: { medianMs: 11.63, p99Ms: 142.88, benchmarkSamples: 100, acceptance: '< 50ms offline — FAIL' },
  confusion: { tn: 10, fp: 0, fn: 2, tp: 9 },
  metrics: [
    { key: 'roc_auc', label: 'ROC-AUC', value: 0.9909, pct: true },
    { key: 'pr_auc', label: 'PR-AUC', value: 0.9924, pct: true },
    { key: 'f1_macro', label: 'F1 (macro)', value: 0.9045, pct: true },
    { key: 'precision', label: 'Precision (malicious)', value: 1.0, pct: true },
    { key: 'recall', label: 'Recall (malicious)', value: 0.8182, pct: true },
  ],
}

export const NLP_DATASETS = [
  { id: 'sms_spam', label: 'SMS Spam', desc: 'UCI SMS Spam Collection — smishing/spam vs. ham' },
  { id: 'phishing_email', label: 'Phishing Email', desc: 'Phishing vs. legitimate email corpus' },
  { id: 'enron_spam', label: 'Enron Spam', desc: 'Enron corporate email spam subset' },
]

export const NLP_MODELS = [
  {
    id: 'deberta_checkpoint',
    label: 'DeBERTa-v3 Checkpoint',
    detail: '15-signal multi-label · score = max(phishing_intent, scam_intent)',
  },
  {
    id: 'rules_baseline',
    label: 'Rules Baseline (Production)',
    detail: 'Heuristic rules backend — currently what the API serves',
  },
]

// Metric definitions shown in the UI.
export const METRIC_DEFS = [
  { key: 'roc_auc', label: 'ROC-AUC', desc: 'Ranking ability across all thresholds (0.5 = random, 1.0 = perfect)' },
  { key: 'pr_auc', label: 'PR-AUC', desc: 'Average precision — recall-weighted ranking, sensitive to class imbalance' },
  { key: 'f1', label: 'F1 Score', desc: 'Harmonic mean of precision & recall at the chosen threshold' },
  { key: 'mcc', label: 'MCC', desc: 'Matthews Correlation Coefficient — balanced measure even on imbalanced data' },
  { key: 'accuracy', label: 'Accuracy', desc: 'Share of all test samples classified correctly' },
  { key: 'balanced_accuracy', label: 'Balanced Acc.', desc: 'Mean of recall on positives and specificity on negatives' },
  { key: 'precision', label: 'Precision', desc: 'Of predicted threats, how many were real threats' },
  { key: 'recall', label: 'Recall', desc: 'Of real threats, how many were caught' },
  { key: 'specificity', label: 'Specificity', desc: 'Of benign samples, how many were correctly cleared' },
  { key: 'fpr', label: 'FPR', desc: 'False-Positive Rate — benign samples wrongly flagged' },
  { key: 'fnr', label: 'FNR', desc: 'False-Negative Rate — threats that slipped through' },
  { key: 'recall_at_1pct_fpr', label: 'Recall @ 1% FPR', desc: 'Threat recall when allowing only 1% false positives' },
  { key: 'brier', label: 'Brier Score', desc: 'Calibration of raw probabilities (0 = perfect)' },
  { key: 'ece', label: 'ECE', desc: 'Expected Calibration Error across 10 probability bins' },
]

export const pct = (v) => (v == null || Number.isNaN(v) ? '—' : `${(v * 100).toFixed(1)}%`)
export const num = (v, d = 3) => (v == null || Number.isNaN(v) ? '—' : Number(v).toFixed(d))
