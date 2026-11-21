# DeBERTa Threat Model Training Report

- **Base Model:** `microsoft/deberta-v3-small`
- **Task:** 15-Signal Multi-Label Cyber Threat Classification
- **Trained At:** 2026-11-21T15:07:31.104853+00:00
- **Training Time:** 1529.9s (cpu)
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
Set `NLP_BACKEND=finetuned` in your `.env` file to activate this model in ThreatSense AI.
