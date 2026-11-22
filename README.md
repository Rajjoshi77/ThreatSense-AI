# ThreatSense AI

ThreatSense AI is a multi-layered threat-analysis API with a React dashboard. It accepts URLs, email messages, SMS/chat text, HTML webpages, images, QR images, and file uploads, then returns a risk score, verdict, detector findings, evidence, and recommended actions.

The backend is built with FastAPI and Python; the dashboard uses React and Vite. The default NLP backend is fine-tuned DeBERTa. Its model weights must be supplied separately because they are too large for a normal GitHub repository.

> **Important:** This is a threat-analysis aid, not antivirus software or a guarantee that an artifact is safe. Review results before taking action. Live URLhaus lookups are optional; when enabled, submitted indicators are sent to that service.

## What’s included

- **22 detectors across five domains:** phishing and social engineering (D01–D09), URL and domain security (D10–D14), web and credential security (D15–D17), email security (D18–D20), and media threats (D21–D22).
- **Six analysis engines:** NLP, URL, web, email, media, and threat intelligence.
- **Seven input types:** `url`, `email`, `sms`, `webpage`, `image`, `qr`, and `file`.
- **Explainable reports:** risk score (0–100), verdict, per-domain breakdown, evidence, and recommended actions.
- **Storage:** SQLite by default for local development; PostgreSQL is configured for Docker Compose.
- **Optional integrations:** QR decoding and image OCR use the system packages listed below. Live URLhaus checks can be enabled with `INTEL_OFFLINE=false`.

The application defaults to fine-tuned DeBERTa. It loads a checkpoint only when training provenance is readable and identifies human-labeled data; the checked-in synthetic prototype is deliberately skipped. If valid weights are missing or inference fails, analysis uses rules and reports the backend that actually ran. URL analysis likewise skips models without reviewed production provenance and uses transparent structural rules. The bundled threat-list samples are synthetic CI fixtures, not active intelligence indicators. See [ML notes](#machine-learning-notes).

## Detector inventory

| Domain | IDs | Detectors |
|---|---|---|
| Phishing & Social Engineering | D01–D09 | Email Phishing; Social Engineering; Spear Phishing; Scam & Fraud; Smishing; Government Impersonation Scam; Financial & Investment Scam; Recruitment Scam; Tech Support Scam |
| URL & Domain Security | D10–D14 | Malicious URL; Brand/Domain Impersonation; Malicious Redirects; URL Obfuscation; IDN/Homograph Attack |
| Web & Credential Security | D15–D17 | Credential Harvesting; Fake Authentication Page; Malicious Webpage |
| Email & Communication Security | D18–D20 | Business Email Compromise (BEC); Spam Email; Suspicious Attachments |
| Multimedia & Image-Based Threats | D21–D22 | QR Code Phishing (Quishing); Screenshot / Image-Based Scam |

## Quick start

### 1. Start the API

Requires Python 3.11 or newer and Node.js 18 or newer.

```bash
cd backend
python -m venv .venv
```

Activate the virtual environment, then install the backend and development dependencies:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

python -m pip install -e ".[dev,ml]"
```

The API uses SQLite by default, so no database setup is needed. Open the interactive API docs at <http://127.0.0.1:8000/docs>; check service status at <http://127.0.0.1:8000/health>.

Configure a trained checkpoint before starting the fine-tuned NLP backend:

```bash
# macOS / Linux
export NLP_BACKEND=finetuned
export NLP_FINETUNED_PATH=/path/to/trained/checkpoint

# Windows PowerShell
$env:NLP_BACKEND = "finetuned"
$env:NLP_FINETUNED_PATH = "C:\\path\\to\\trained\\checkpoint"

uvicorn app.main:app --reload --port 8000
```

A local checkpoint directory must contain trained weights, tokenizer files, and a `model.meta.json` whose `training_data` is `human_labeled`; unverified or synthetic checkpoints are skipped. For a Hugging Face model, set `NLP_FINETUNED_PATH` to its `owner/model` ID and include the same provenance metadata in the repository. A private model also requires `HF_TOKEN`. If loading or inference fails, the API logs a warning and uses the rules backend.

QR decoding and screenshot OCR are optional. For those features, install Tesseract and ZBar on the host:

```bash
# Ubuntu / Debian
sudo apt-get install tesseract-ocr libzbar0

# macOS
brew install tesseract zbar
```

### 2. Start the dashboard

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open <http://localhost:5173>. For a non-local API, set `VITE_API_URL` in `frontend/.env.local` to the backend base URL (for example, `https://api.example.com`). A configured backend API key is not automatically added by the dashboard; use an API client that sends the configured key header.

### Run with Docker Compose

From the repository root, with Docker Compose installed:

```bash
docker compose up --build
```

This starts the API and PostgreSQL. Apply the initial database migration once the API is running:

```bash
docker compose exec api alembic upgrade head
```

The dashboard is a separate Vite app; use the frontend steps above to run it locally. The API is available at <http://localhost:8000/docs>.

For production, replace the development `SECRET_KEY`, configure any API key and allowed CORS origins, and use deployment-specific database credentials. Do not commit secrets or production data to `.env` or the repository.

## API overview

Interactive request/response schemas are available at `/docs` and `/redoc`.

### Analyze text

`POST /analyze` accepts JSON for URL, email, and SMS artifacts:

```json
{
  "type": "url",
  "raw_content": "https://example.com/login",
  "metadata": {}
}
```

### Analyze a file

`POST /analyze` also accepts `multipart/form-data` with a `type` field and a `file` field. For example:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -F "type=image" \
  -F "file=@screenshot.png"
```

For an HTML upload, use `type=webpage`; for a QR image, use `type=qr`. Upload type, extension, MIME, and size are validated by the API.

### Other endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | Service information and links to the API docs and health check |
| `GET /health` | Health, database status, active NLP backend, and detector count |
| `GET /detectors` | Registered detectors grouped by domain |
| `POST /analyze` | Analyze a JSON artifact or multipart file upload |
| `GET /analyses/{analysis_id}` | Retrieve a stored analysis report |

Requests are rate-limited. API-key authentication is disabled when `API_KEY` is empty; when configured, API clients must send the key using the header named by `API_KEY_HEADER` (default `X-API-Key`).

## Tests and lint

Install the backend development dependencies as shown above, then run the actual test suite from `backend/`:

```bash
python -m pytest tests/ -q --tb=short
python -m ruff check app/ tests/
```

Run the frontend production build from `frontend/`:

```bash
npm run build
```

## Configuration

Backend settings are read from environment variables and an optional `.env` file in the backend’s working directory. The root `.env.example` documents available settings. For local API development, copy it to `backend/.env`; for Docker Compose, copy it to the repository-root `.env`, which Compose reads automatically. Replace development values and keep secrets out of Git.

| Setting | Purpose |
|---|---|
| `DATABASE_URL` | Async database URL; defaults to local SQLite |
| `NLP_BACKEND` | NLP backend selection; defaults to `finetuned`, with automatic rules fallback if unavailable |
| `NLP_FINETUNED_PATH` | Local trained checkpoint directory or Hugging Face model ID for `finetuned` |
| `NLP_MIN_MEMORY_MB` | Minimum container memory to load DeBERTa; below it, use rules (default `1536`) |
| `HF_TOKEN` | Hugging Face access token when using a private model repository; keep it secret |
| `API_KEY` | Optional API authentication; empty disables authentication |
| `API_KEY_HEADER` | Header name for API-key authentication |
| `CORS_ORIGINS` | Comma-separated allowed origins, or `*` |
| `UPLOAD_DIR` | Upload storage path; defaults to `./uploads` |
| `INTEL_OFFLINE` | Set to `false` to enable the optional live URLhaus lookup |
| `VITE_API_URL` | Frontend API base URL, set in the frontend environment |

Threat-intelligence list locations are in `backend/app/engines/intel/data/`; synthetic CI fixture rows are intentionally not active blocklist indicators. Configure only sourced, reviewed feeds before relying on local matches. When `INTEL_OFFLINE=false`, the backend sends analyzed URLs to URLhaus for lookup; consider this privacy implication before enabling live checks.

## Machine-learning notes

- **Default mode:** `NLP_BACKEND=finetuned`. If its checkpoint is missing, inference fails, or the container memory limit is below `NLP_MIN_MEMORY_MB` (default 1536 MiB), the service uses rules and the analysis report identifies `rules` as the backend that ran. This allows the API to start within small memory limits such as Render's 512 MiB free instance; DeBERTa requires a larger instance. Set `NLP_BACKEND=rules` to select rules directly.
- **URL model:** A URL classifier is loaded only when its metadata identifies reviewed `production` training. Missing metadata or synthetic/unknown modes are skipped; structural rule-based scoring is the fallback and is a triage score, not a calibrated probability.
- **Zero-shot NLP:** `NLP_BACKEND=zeroshot` requires the optional Transformers stack and model availability; `NLP_ZEROSHOT=true` enables model loading. Without it, the backend falls back to rules.
- **Fine-tuned NLP:** Training code and notes live under `ml/`. The checkpoint weights are not included in Git. A complete local or Hugging Face checkpoint must provide readable `model.meta.json` provenance with `training_data: human_labeled`; unknown or synthetic provenance is rejected. Configure `NLP_FINETUNED_PATH` for local or Hub checkpoints, and `HF_TOKEN` for private Hub access. If a suitable checkpoint is unavailable, the service falls back to rules and reports the effective backend.
- **Training quality:** The committed NLP metadata describes an unvalidated synthetic prototype and the local URL-model report describes synthetic CI data; neither is enabled as a production classifier. NLP training requires at least 50 reviewed examples with source and human annotator provenance. The `--small` synthetic mode requires a separate output directory. Independently evaluate any candidate on a representative, human-reviewed holdout before deployment. Software tests and smoke checks are not accuracy measurements.
- **Training data and intelligence:** `ml/data/README.md` explains intended sources. Synthetic examples in the bundled intel lists are inactive; only sourced, reviewed indicators should be configured. Review dataset licences and label quality before operational use.

## Repository layout

```text
backend/        FastAPI application, detectors, engines, migrations, and tests
frontend/       React + Vite dashboard
ml/             Optional model training code, model metadata, and data guidance
examples/       Small benign and suspicious sample artifacts
validation/     Standalone detector validation utility
docs/           Seminar and project reports
Makefile        Common local-development commands
backend/Dockerfile  Backend container definition
docker-compose.yml  Local API and PostgreSQL services
render.yaml     Render deployment blueprint
```

Additional project notes:

- [Project poster — PowerPoint](docs/ThreatSense_AI_Project_Poster.pptx) · [print-ready PDF](docs/ThreatSense_AI_Project_Poster.pdf)
- [Developer architecture guide](DEVELOPER_README.md)
- [Detection behavior and limitations](DETECTION_REPORT.md)
- [Presentation and future scope](PRESENTATION_AND_FUTURE_SCOPE.md)
- [ML data sources](ml/data/README.md)

For the detector inventory and scoring implementation, see `backend/app/detectors/`, `backend/app/aggregator/aggregator.py`, and `backend/app/core/registry.py`.
