# DeBERTa Threat Model Training Report

- **Base Model:** `microsoft/deberta-v3-small`
- **Task:** 15-Signal Multi-Label Cyber Threat Classification
- **Trained At:** 2026-11-22T06:50:55.507306+00:00
- **Training Time:** 258.1s (cpu)
- **Training Data:** synthetic bootstrap examples (not independently reviewed)
- **Signals Output:**
  - `urgency`
  - `fear`
  - `authority`
  - `reward_scarcity`
  - `financial_intent`
  - `credential_request`
  - `manipulation`
  - `phishing_intent`
  - `scam_intent`
  - `investment_context`
  - `recruitment_context`
  - `tech_support_context`
  - `government_service_claim`
  - `payment_request`
  - `remote_access_request`

## Limitations

This checkpoint was trained on synthetic bootstrap examples, is not independently
evaluated, and showed nearly uniform signal scores for benign and threat text in
local smoke checks. The backend therefore rejects it and uses the rules fallback.
These checks are software diagnostics, not evidence of detection accuracy.

## Production Usage

Do not use this checkpoint in production. Retrain with reviewed data and
independently evaluate it before enabling it for threat decisions.


