# DeBERTa Threat Model Training Report

- **Base Model:** `microsoft/deberta-v3-small`
- **Task:** 15-Signal Multi-Label Cyber Threat Classification
- **Trained At:** 2026-11-22T06:50:55.507306+00:00
- **Training Time:** 258.1s (cpu)
- **Training Data:** human_labeled
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

## Production Usage
Set `NLP_BACKEND=finetuned` and configure `NLP_FINETUNED_PATH` to activate a
trained checkpoint in ThreatSense AI.


