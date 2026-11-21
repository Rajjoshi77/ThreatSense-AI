# 🛡️ ThreatSense AI — Developer Architecture & Implementation Guide

Welcome to the internal engineering documentation for **ThreatSense AI**, a multi-layered cybersecurity threat detection platform that analyses URLs, emails, SMS messages, webpages, images, QR codes, and files across **22 specialized detectors** categorized into **5 threat domains**.

---

## 📑 Table of Contents

1. [High-Level Architecture & Lifecycle](#-high-level-architecture--lifecycle)
2. [Directory & File Map](#-directory--file-map)
3. [Key Core Files & Their Responsibilities](#-key-core-files--their-responsibilities)
4. [Input Normalization & Upload Hardening](#-input-normalization--upload-hardening)
5. [The 6 Intelligence Engines](#-the-6-intelligence-engines)
6. [The 22 Detectors & Registry Pattern](#-the-22-detectors--registry-pattern)
7. [The Math of Threat Detection: Noisy-OR & Scoring](#-the-math-of-threat-detection-noisy-or--scoring)
8. [Explainability Engine & URL Defanging](#-explainability-engine--url-defanging)
9. [Frontend React Dashboard](#-frontend-react-dashboard)
10. [How to Add a New Detector](#-how-to-add-a-new-detector)
11. [Running, Testing & Developing Locally](#-running-testing--developing-locally)

---

## 🏛️ High-Level Architecture & Lifecycle

Every submission passes through a deterministic, layered pipeline:

```
[ Client / Browser / API Consumer ]
                │
                ▼  POST /analyze (JSON or Multipart)
┌─────────────────────────────────────────────────────────┐
│ 1. API Route Layer (app/api/routes/analyze.py)           │
│    - Rate Limiting (slowapi: 30 req/min)                │
│    - Optional API Key Authentication                    │
│    - Initial SQLite / PostgreSQL row created            │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│ 2. Normalizer & Upload Hardener (app/input/)            │
│    - MIME validation, magic byte checking (anti-spoof)  │
│    - Strict size cap enforcement                        │
│    - Produces a unified Artifact dataclass              │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│ 3. AnalysisContext & Shared Engine Cache (app/core/)    │
│    - Double-checked asynchronous locking                │
│    - Lazily computes expensive engines ONCE per run     │
└──────────────────────────┬──────────────────────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  NLP Engine  │    │  URL Engine  │    │  Web Engine  │
│  (Lexicon/NLI)│    │(Entropy/Brand)│   │ (DOM/JS eval)│
└──────────────┘    └──────────────┘    └──────────────┘
       ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Email Engine │    │ Media Engine │    │ Intel Engine │
│(SPF/DKIM/BEC)│    │ (QR / OCR)   │    │(Blocklists)  │
└──────────────┘    └──────────────┘    └──────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│ 4. 22 Specialized Detectors (D01 – D22)                  │
│    - Self-registered via @register_detector             │
│    - Parallel / sequential signal evaluation            │
│    - Return DetectionResult with Evidence & Score       │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│ 5. Risk Aggregator (app/aggregator/aggregator.py)       │
│    - Noisy-OR domain combination: 1 - ∏(1 - s_i)        │
│    - Domain weighting (D1: 30%, D2: 30%, D3: 20%...)    │
│    - Critical evidence floor (≥ 70) & Intel floor (≥ 80)│
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│ 6. Explainer & Defanger (app/explain/explainer.py)      │
│    - Defangs dangerous URLs (e.g. hxxps://evil[.]com)   │
│    - Assembles plain-English verdict summaries          │
│    - Produces actionable recommendations                │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│ 7. Database Persistence & JSON Response                 │
│    - SQLAlchemy AsyncSession saves Analysis & Results   │
│    - Response returned to Client / React Dashboard      │
└─────────────────────────────────────────────────────────┘
```

---

## 📂 Directory & File Map

```
ThreatSenseAI/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI entry point, CORS, lifecycle, rate limiter
│   │   ├── api/
│   │   │   └── routes/
│   │   │       ├── analyze.py          # /analyze (JSON & multipart) & /analyses/{id}
│   │   │       ├── detectors.py        # /detectors registry introspector
│   │   │       └── health.py           # /health status endpoint
│   │   ├── core/
│   │   │   ├── config.py               # Pydantic Settings & environment variables
│   │   │   ├── context.py              # AnalysisContext lazy caching & thread-safety
│   │   │   ├── registry.py             # Detector registry & auto-discovery decorator
│   │   │   ├── rate_limit.py           # SlowAPI rate limiter setup
│   │   │   ├── security.py             # API Key verification dependency
│   │   │   └── logging_config.py       # Formatted logging setup
│   │   ├── db/
│   │   │   ├── models.py               # SQLAlchemy ORM models (Analysis, DetectionResultDB)
│   │   │   └── session.py              # Async SQLAlchemy engine & session factory
│   │   ├── input/
│   │   │   ├── uploader.py             # Upload size cap, magic bytes & MIME security
│   │   │   └── normalizers/            # Normalizers for URL, Email, SMS, Web, Image, QR, File
│   │   ├── fetcher/
│   │   │   └── safe_fetcher.py         # SSRF-safe HTTP client with redirect loop protection
│   │   ├── engines/
│   │   │   ├── nlp/                    # Rules lexicon, zero-shot NLI & ensemble backends
│   │   │   ├── url/                    # Entropy, Brand Levenshtein, XGBoost model, Homoglyphs
│   │   │   ├── web/                    # DOM parser, hidden input analysis, obfuscated JS
│   │   │   ├── email/                  # RFC 822 parsing, SPF/DKIM/DMARC, BEC signal engine
│   │   │   ├── media/                  # PyZbar QR reader & PyTesseract OCR extractor
│   │   │   └── intel/                  # Local blocklists (IPs, domains, hashes) + URLhaus
│   │   ├── detectors/
│   │   │   ├── base.py                 # Abstract BaseDetector interface
│   │   │   ├── d1_phishing/            # Detectors D01 - D09 (Phishing, Social Eng, Scams)
│   │   │   ├── d2_url/                 # Detectors D10 - D14 (Typosquat, Shortener, Homoglyph, etc.)
│   │   │   ├── d3_web/                 # Detectors D15 - D17 (Credential Harvest, Fake Auth, Obfuscation)
│   │   │   ├── d4_email/               # Detectors D18 - D20 (BEC, Spam, Suspicious Attachments)
│   │   │   └── d5_media/               # Detectors D21 - D22 (Quishing, Screenshot Scam)
│   │   ├── aggregator/
│   │   │   └── aggregator.py           # Noisy-OR probabilistic risk combiner & overrides
│   │   ├── explain/
│   │   │   └── explainer.py            # Natural language summarizer & URL defanging
│   │   └── schemas/
│   │       └── schemas.py              # Pydantic schemas (Artifact, DetectionResult, RiskReport)
│   ├── alembic/                        # Database migration scripts
│   ├── tests/                          # Complete pytest suite (398+ unit/integration tests)
│   └── pyproject.toml                  # Backend package dependencies and configuration
├── frontend/
│   ├── src/
│   │   ├── App.jsx                     # Interactive React dashboard UI
│   │   ├── index.css                   # Dark-mode styling, glowing metrics, score rings
│   │   └── main.jsx                    # Vite React entry point
│   ├── package.json                    # Frontend dependencies
│   └── vite.config.js                  # Vite bundler configuration
└── DEVELOPER_README.md                 # This document
```

---

## 🔑 Key Core Files & Their Responsibilities

### 1. `backend/app/main.py`
The application entry point.
- Configures structured logging.
- Imports `app.detectors`, which triggers `@register_detector` decorators across all detector modules so that every detector is registered before the server starts handling requests.
- Configures CORS middleware for seamless local React development.
- Configures `slowapi` rate limiting.
- Initializes SQLite tables in development mode during the startup event.

### 2. `backend/app/core/context.py` (`AnalysisContext`)
The state container for an individual analysis run.
- **Lazy Engine Execution**: If multiple detectors (e.g., all 9 detectors in Domain 1) require NLP analysis, the NLP engine is executed **only once** on first access.
- **Double-Checked Locking**: Implements per-engine `asyncio.Lock` to guarantee safe concurrent evaluation without duplicate execution.
- **Failure Tracking**: Records engine failures gracefully so that detector confidence is appropriately lowered rather than failing the entire request.

### 3. `backend/app/api/routes/analyze.py`
Coordinates the entire lifecycle for `POST /analyze`.
- Accepts standard JSON payloads or `multipart/form-data` file uploads.
- Normalizes input into an `Artifact` dataclass.
- Initializes `AnalysisContext`.
- Iterates over all registered detectors, collects results, invokes `RiskAggregator`, enriches the result with `Explainer`, saves the analysis to SQLite/PostgreSQL, and returns the response.

### 4. `backend/app/aggregator/aggregator.py`
The mathematical scoring center of ThreatSense AI.
- Merges detector scores within each domain using the probabilistic **Noisy-OR** formula.
- Combines domain scores using configurable weights.
- Applies hard-override security floors for verified threat intel and critical evidence.

### 5. `backend/app/explain/explainer.py`
Human-in-the-loop security reporting.
- Defangs dangerous URLs in the text evidence (`http://` -> `hxxp://`, `.` -> `[.]`).
- Formulates plain-English explanations and actionable mitigation advice.

---

## 🛡️ Input Normalization & Upload Hardening

The `app/input/` subsystem ensures malicious inputs cannot compromise the server:

1. **Size Caps**:
   - Emails (.eml): 25 MB
   - Webpages (HTML): 5 MB
   - Images & Screenshots: 20 MB
   - QR Codes: 10 MB
   - General Files: 50 MB
2. **Magic-Byte Inspection (`app/input/uploader.py`)**:
   - Validates file headers regardless of user-provided extension or Content-Type header.
   - Blocks raw PE executables (`MZ` header), ELF binaries, and unauthorized executable archives from unprivileged upload endpoints.
3. **Randomized On-Disk Storage**:
   - Uploaded files are assigned cryptographic UUID filenames (e.g., `4a7f29b...a1.pdf`) and stored with restricted permissions (`0o600`).
   - Original filenames are preserved exclusively in metadata for analysis.

---

## ⚙️ The 6 Intelligence Engines

The platform separates feature extraction (Engines) from threat classification (Detectors). This ensures zero code duplication.

| Engine | Path | Capabilities & Internals |
|---|---|---|
| **NLP Engine** | `app/engines/nlp/` | Evaluates urgency, fear, financial lures, authority impersonation, credential solicitation using high-performance regex lexicons, zero-shot NLI, or ensemble backends. |
| **URL Engine** | `app/engines/url/` | Computes Shannon entropy, Levenshtein distance against 100+ global brands, TLD reputation scores, homoglyph attack detection, and pre-trained XGBoost URL classifier scoring. |
| **Web Engine** | `app/engines/web/` | Parses HTML via BeautifulSoup, searches for hidden password inputs, iframe overlays, fake login action targets, and obfuscated JavaScript (`eval`, `unescape`, hex encoding). |
| **Email Engine** | `app/engines/email/` | Parses RFC 822 email structures, validates SPF / DKIM / DMARC authentication headers, identifies From vs. Reply-To mismatches (BEC), and inspects attachment MIME types. |
| **Media Engine** | `app/engines/media/` | Decodes QR codes using `pyzbar` and extracts text from screenshot lures using `pytesseract` OCR. |
| **Intel Engine** | `app/engines/intel/` | Checks local hash, IP, and domain blocklists with rapid hashset lookups and queries URLhaus threat feeds. |

---

## 🔍 The 22 Detectors & Registry Pattern

All detectors inherit from `BaseDetector` ([backend/app/detectors/base.py](file:///d:/degree/sem%207/ThreatSenseAI-master/backend/app/detectors/base.py)) and use the `@register_detector` decorator:

### Domain 1: Phishing & Social Engineering (`d1_phishing`)
- **D01 Email Phishing**: Detects credential harvesting lures and deceptive email calls to action.
- **D02 Social Engineering**: Evaluates psychological manipulation, urgency, and fear triggers.
- **D03 Spear Phishing**: Identifies hyper-personalized executive and targeted attacks.
- **D04 Scam & Fraud**: Catches prize, lottery, inheritance, and advance-fee fraud.
- **D05 Smishing**: Analyzes SMS messages containing shortlinks or suspicious urgency.
- **D06 Government Scams**: Detects fake IRS, HMRC, Aadhaar, police, or passport alerts.
- **D07 Financial Investment**: Flags fake crypto platforms, guaranteed returns, and pump-and-dump lures.
- **D08 Recruitment Scams**: Uncovers fake job postings requesting upfront security deposits.
- **D09 Tech Support Scams**: Flags fake Windows/Apple security popups prompting remote tool access (AnyDesk, TeamViewer).

### Domain 2: URL & Domain Security (`d2_url`)
- **D10 Typosquatting**: Identifies lookalike domains (`paypa1.com`, `g00gle.com`) via Levenshtein brand matching.
- **D11 URL Shortener Abuse**: Evaluates abused link shorteners (`bit.ly`, `tinyurl`) masking malicious endpoints.
- **D12 Homoglyph Attacks**: Detects Cyrillic and Greek Unicode lookalikes spoofing ASCII domains.
- **D13 Redirect Chains**: Traces multi-hop cloaking redirects.
- **D14 Suspicious TLD**: Flags high-abuse TLDs (`.xyz`, `.top`, `.click`, `.zip`).

### Domain 3: Web & Credential Security (`d3_web`)
- **D15 Credential Harvesting**: Finds off-domain password submission targets and hidden card inputs.
- **D16 Fake Auth Pages**: Compares page branding against actual form submission endpoints.
- **D17 Malicious Webpages**: Flags inline `eval()`, base64 payloads, and drive-by exploit patterns.

### Domain 4: Email & Communication Security (`d4_email`)
- **D18 Business Email Compromise (BEC)**: Detects CEO fraud, wire transfer requests, and display name spoofing.
- **D19 Spam Detection**: Analyzes high-frequency spam keywords and bulk mailing headers.
- **D20 Suspicious Attachments**: Identifies double extensions (`invoice.pdf.exe`), macro-enabled Office files, and dangerous scripts.

### Domain 5: Multimedia & Image-Based Threats (`d5_media`)
- **D21 QR Phishing (Quishing)**: Extracts embedded URLs from QR codes and feeds them to Domain 2 detectors.
- **D22 Screenshot Scams**: Runs OCR text extraction on images to detect WhatsApp/banking scam screenshots.

---

## 🧮 The Math of Threat Detection: Noisy-OR & Scoring

A simple arithmetic average fails in security: 9 safe signals + 1 confirmed Trojan would average out to 10% risk (false negative). ThreatSense AI uses **Probabilistic Noisy-OR** combination.

### 1. Domain-Level Noisy-OR
For detector scores $s_1, s_2, \dots, s_n \in [0, 1]$ within a domain:

$$S_{\text{domain}} = 1 - \prod_{i=1}^{n} (1 - s_i)$$

*Example*: If Detector A scores 0.60 and Detector B scores 0.70:
$$S_{\text{domain}} = 1 - (1 - 0.60)(1 - 0.70) = 1 - (0.40 \times 0.30) = 1 - 0.12 = 0.88$$

### 2. Overall Platform Risk Score
The platform score combines domain scores using weights:
- Domain 1 (Phishing / SE): **30%**
- Domain 2 (URL & Domain): **30%**
- Domain 3 (Web Security): **20%**
- Domain 4 (Email Security): **15%**
- Domain 5 (Media Threats): **5%**

$$\text{Raw Score} = \sum_{d \in \{D1..D5\}} w_d \times S_d \times 100$$

### 3. Hard Security Overrides
- **Intel Blocklist Match**: If known malicious hash/URL matches local or URLhaus blocklist $\rightarrow$ **Floor at 80/100 (MALICIOUS)**.
- **CRITICAL Evidence**: If any detector flags a `CRITICAL` severity indicator $\rightarrow$ **Floor at 70/100**.

### 4. Verdict Thresholds
- **MALICIOUS**: Risk Score $\ge 75$
- **LIKELY_MALICIOUS**: Risk Score $\ge 50$
- **SUSPICIOUS**: Risk Score $\ge 25$
- **SAFE**: Risk Score $< 25$

---

## 🛡️ Explainability Engine & URL Defanging

Raw security reports often contain dangerous active links. The `Explainer` module:

1. **Defangs URLs**: Automatically converts active hyperlinks in all evidence descriptions into harmless text:
   - `http://evil.com/login` $\rightarrow$ `hxxp://evil[.]com/login`
   - `https://phish.xyz` $\rightarrow$ `hxxps://phish[.]xyz`
2. **Contextual Summaries**: Generates plain-English threat narratives suitable for non-technical users.
3. **Prescriptive Action Guidance**: Outputs immediate security advice tailored to the specific threat type (e.g. "Do not enter credentials", "Delete message", "Report to security team").

---

## 💻 Frontend React Dashboard

Located in `frontend/src/`:
- **State-of-the-art Dark UI**: Built with responsive CSS variables, glassmorphic cards, and glowing threat severity badges.
- **Dynamic Score Ring**: SVG-based animated radial gauge displaying real-time risk scores (0–100).
- **Artifact Mode Switcher**: Seamlessly toggles between URL input, email text/RFC822 upload, SMS body, webpage HTML, QR images, and attachment files.
- **Evidence Inspector**: Collapsible cards ordered by severity (`CRITICAL` $\rightarrow$ `HIGH` $\rightarrow$ `MEDIUM` $\rightarrow$ `LOW` $\rightarrow$ `INFO`) with defanged URLs and detector IDs.
- **Domain Breakdown Bars**: Visual horizontal gauges showing individual risk contribution from all 5 threat domains.

---

## 🛠️ How to Add a New Detector

Adding a new detector takes fewer than 5 minutes thanks to the registry pattern:

1. Create a new file in the appropriate domain folder, e.g., `backend/app/detectors/d1_phishing/d23_my_new_detector.py`.
2. Inherit from `BaseDetector` and decorate with `@register_detector`:

```python
from app.core.registry import register_detector
from app.detectors.base import BaseDetector
from app.schemas.schemas import Artifact, ArtifactType, DetectionResult, Evidence, EvidenceSeverity, Verdict

@register_detector
class MyNewDetector(BaseDetector):
    detector_id = "d23_my_new_detector"
    name = "Custom Threat Detector"
    domain = "Phishing & Social Engineering"
    domain_id = "d1"
    accepted_artifact_types = [ArtifactType.EMAIL, ArtifactType.SMS]
    required_engines = ["nlp"]

    async def detect(self, artifact: Artifact, ctx: AnalysisContext) -> DetectionResult:
        nlp_signals = await ctx.get_nlp_signals()
        
        evidence = []
        score = 0.0
        
        if nlp_signals.urgency_score > 0.8:
            score = 0.85
            evidence.append(Evidence(
                detector_id=self.detector_id,
                title="Extreme Urgency Detected",
                description="The text exhibits high-pressure coercive tactics.",
                severity=EvidenceSeverity.HIGH,
                confidence=0.9,
                weight=0.85,
            ))
            
        return DetectionResult(
            detector_id=self.detector_id,
            name=self.name,
            domain=self.domain,
            domain_id=self.domain_id,
            score=score,
            verdict=Verdict.MALICIOUS if score >= 0.75 else Verdict.SAFE,
            confidence=0.9,
            evidence=evidence,
            signals_used=["nlp.urgency_score"],
            ran=True,
        )
```
3. Export the detector in `backend/app/detectors/__init__.py`.
4. Run `pytest` to verify the new detector. It will be automatically discovered by the API and Dashboard without any other configuration!

---

## 🚀 Running, Testing & Developing Locally

### 1. Start Backend (FastAPI)
```powershell
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000
```
- Interactive Swagger API: **http://127.0.0.1:8000/docs**
- Health Check: **http://127.0.0.1:8000/health**

### 2. Start Frontend (React + Vite)
```powershell
cd frontend
npm run dev
```
- Dashboard: **http://localhost:5173**

### 3. Run the Test Suite
```powershell
cd backend
.\.venv\Scripts\pytest.exe -q --tb=short
# 399 passed, 1 xpassed in ~80s (includes the DeBERTa NLP tests)
```

### 4. Train the DeBERTa NLP Model (optional)

The fine-tuned backend is off by default (`NLP_BACKEND=rules`). To enable
`NLP_BACKEND=finetuned` you need the model weights, which are gitignored
(~542 MB). See [`ml/artifacts/nlp_model/README.md`](ml/artifacts/nlp_model/README.md).

```powershell
# from the repository root, using the interpreter you installed the ML stack into
pip install -r ml/training/requirements.txt
python ml/training/train_nlp_deberta.py --epochs 4          # full run
python ml/training/train_nlp_deberta.py --small --epochs 1 --out .\tmp_model  # smoke test
```

- Artifacts land in `ml/artifacts/nlp_model/` by default; use `--out` to write elsewhere
  so a smoke test never overwrites a trained model.
- Train with `torch` 2.7.x + `transformers` 4.x. A `transformers` 5.x build produced
  **NaN loss** in testing; the trainer aborts on non-finite loss rather than saving garbage.
- The backend venv (`backend/.venv`) is for running the API and tests. Keep training in a
  separate environment that satisfies `ml/training/requirements.txt`.

Verify the model is actually being used:

```powershell
cd backend
.\.venv\Scripts\python.exe -c "from app.core.config import settings; print(settings.NLP_BACKEND.value)"
# finetuned
```
