# ThreatSense AI — Threat Detection & Analysis Guide

> **Project:** ThreatSense AI  
> **Architecture:** 5 Detection Domains · 22 Specialized Detectors · Multi-Engine Pipeline  
> **Engines:** NLP Engine, URL Heuristics, Web DOM Parser, Email Forensics, Media/QR & OCR, Threat Intelligence

---

## 1. The Big Picture: How Detection Works in 3 Steps

Whenever an artifact is submitted to ThreatSense AI, it flows through a sequential three-step pipeline:

```
[ User Input ]
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  Step 1: Normalization & Intelligence Engines          │
│  • NLP Lexicon Engine (15 psychological signals)       │
│  • URL & Domain Feature Extractor (28 features)        │
│  • Web DOM & Form Parser (BeautifulSoup)               │
│  • RFC 822 Email Forensics Parser                      │
│  • Media Engine (QR Code pyzbar + Tesseract OCR)       │
│  • Threat Intelligence (URLhaus + Local Blocklists)    │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│  Step 2: 22 Specialized Detectors Across 5 Domains     │
│  • Domain 1: Phishing & Social Engineering (D01–D09)   │
│  • Domain 2: Malicious URLs & Domains (D10–D14)        │
│  • Domain 3: Web & Credential Security (D15–D17)       │
│  • Domain 4: Email & Communication Security (D18–D20)  │
│  • Domain 5: Multimedia & Image Threats (D21–D22)      │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│  Step 3: Risk Aggregation & Explainer                  │
│  • Noisy-OR Per-Domain Score Amplification             │
│  • Weighted Domain Aggregation                         │
│  • Critical Threat Floor Override (min 70/100)         │
│  • Explainable Output & Evidence Generation            │
└────────────────────────────────────────────────────────┘
```

1. **Extraction (Engines):** The raw input is parsed into clean signals (text semantics, links, DOM forms, email headers, image text, or file magic bytes).
2. **22 Detectors:** Specialized security rules evaluate the signals (*e.g., Is the domain typosquatted? Is there an SPF failure? Is an input form submitting credentials to an external host?*).
3. **Aggregator & Explainer:** Scores are synthesized into a final **Risk Score (0–100)** and a categorized verdict (`Safe`, `Suspicious`, `Likely Malicious`, or `Malicious`).

---

## 2. In-Depth: How Each Input Type is Analyzed

### 🔗 1. URLs (Links)
* **Target:** Web addresses, redirects, and query parameters.
* **Extraction:** 28-dimensional feature vector extracted purely from the URL string (entropy, token count, TLD risk, path patterns, IP presence).
* **Detection Logic:**
  * **Brand Impersonation & Typosquatting:** Calculates Levenshtein distance and token matches against popular brands (e.g., `paypa1.com`, `apple-security-check.xyz`).
  * **Homoglyph & Punycode Attacks:** Detects lookalike Unicode characters substituted into domain names (e.g., Cyrillic `а` instead of Latin `a`).
  * **IP Host Detection:** Flags URLs using raw IP addresses (e.g., `http://192.168.1.1/login`) rather than registered domain names.
  * **Suspicious TLDs & Shorteners:** Scores high-risk top-level domains (`.xyz`, `.top`, `.click`, `.zip`) and identifies link shorteners (`bit.ly`, `tinyurl.com`) concealing the true destination.
  * **Entropy & Token Stacking:** Detects randomly generated, high-entropy subdomain strings and deceptive keywords (`paypal.com.verify-account.attacker.net`).

---

### 📧 2. Emails (RFC 822 / `.eml`)
* **Target:** Complete email payloads including MIME boundaries, headers, body text, and attachments.
* **Extraction:** Separates header metadata (`From`, `Reply-To`, `Authentication-Results`), extracts plain-text and HTML parts, and isolates attachments.
* **Detection Logic:**
  * **Display Name Spoofing:** Compares the friendly display name with the actual sending address (e.g., Display Name: `"PayPal Support"` vs. Actual Address: `support@evil-hacker.com`).
  * **SPF / DKIM / DMARC Validation:** Parses header authentication results to flag forged sender domains.
  * **From vs. Reply-To Mismatch:** Flags emails configured to route replies to a different, untrusted domain.
  * **Business Email Compromise (BEC):** Detects executive impersonation combined with urgent financial requests (wire transfers, invoice modifications).
  * **Embedded Payload Forwarding:** Recursively extracts all links and attachments, feeding them into the URL and File detection pipelines.

---

### 💬 3. SMS & Chat Messages
* **Target:** SMS text, WhatsApp messages, and direct messaging strings.
* **Extraction:** Plain text content and regex-extracted URLs.
* **Detection Logic:**
  * **15-Signal NLP Lexicon Engine:** Evaluates text against 15 psychological manipulation dimensions:
    * **Urgency:** *"Account suspended in 24 hours"*, *"Act immediately"*.
    * **Fear & Legal Threats:** *"Arrest warrant"*, *"Legal proceedings"*, *"Tax penalty"*.
    * **Credential Harvesting:** Explicit requests for OTP, PIN, password, CVV, or Aadhaar numbers.
    * **Financial Scams & Lottery:** *"You won $10,000"*, *"Guaranteed daily return"*, *"Crypto transfer"*.
    * **Authority Impersonation:** Impersonating tax authorities (IRS, HMRC), law enforcement, or postal couriers (DHL, FedEx).
  * **Smishing Combination:** Correlates high-urgency psychological triggers with embedded shortlinks or unknown domains.

---

### 🌐 4. Webpages (HTML / DOM)
* **Target:** Webpage source code, login forms, scripts, and links.
* **Extraction:** Parsed with BeautifulSoup to build an AST of forms, input types, scripts, and external references.
* **Detection Logic:**
  * **Credential Harvesting:** Identifies `<input type="password">` or credit card fields on unauthorized or unbranded domains.
  * **Off-Site Form Actions:** Detects forms configured to transmit user data to external hosts (`<form action="http://attacker.com/collect.php">`).
  * **Insecure Transmissions:** Flags authentication fields submitted over unencrypted HTTP.
  * **JavaScript Obfuscation:** Detects patterns like `eval()`, packed hex scripts, and `document.write()` used to hide exploit payloads from browser scanners.

---

### 🖼️ 5. Images (Screenshots & Scams)
* **Target:** Uploaded screenshot images, photo lures, and receipts.
* **Extraction:** Magic bytes validation + Optical Character Recognition (OCR) via Tesseract.
* **Detection Logic:**
  * **OCR Text Extraction:** Reads all textual content rendered inside the image (e.g., screenshots of fake bank SMS alerts, lottery notifications, or impersonated WhatsApp conversations).
  * **Pipelined NLP:** Automatically routes the extracted text into the 15-signal NLP engine to detect coercion, scams, or credential prompts.
  * **Structural Integrity:** Analyzes image headers for anomalous trailing payloads or steganographic markers.

---

### ⬛ 6. QR Codes ("Quishing")
* **Target:** 2D QR Code barcodes in image format.
* **Extraction:** Decoded into underlying strings using `pyzbar`.
* **Detection Logic:**
  * **Payload Resolution:** Decodes the binary image matrix to uncover the target URL or action string.
  * **Chained Multi-Engine Analysis:** Passes the decoded payload directly into:
    1. The **URL Heuristics Engine** (evaluating typosquatting, shorteners, and redirects).
    2. The **Threat Intelligence Provider** (checking against URLhaus and known malicious blocklists).

---

### 📁 7. Files
* **Target:** Suspicious attachments and binary uploads.
* **Extraction:** Header analysis, magic-byte inspection, and extension parsing.
* **Detection Logic:**
  * **Magic-Byte MIME Verification:** Reads the initial 8 bytes of the file to determine its authentic MIME type, defeating extension spoofing (e.g., an executable `.exe` renamed to `invoice.pdf`).
  * **Double Extension Detection:** Flags evasive naming conventions like `report.pdf.exe` or `statement.docx.bat`.
  * **Dangerous Script Extensions:** Identifies executable and script extensions (`.bat`, `.vbs`, `.ps1`, `.cmd`, `.jar`, macro-enabled `.docm`/`.xlsm`).

---

## 3. The 22 Detectors & 5 Threat Domains

| Domain | ID | Detector Name | Primary Threats Detected |
|:---|:---:|:---|:---|
| **Domain 1: Phishing & Social Engineering**<br>*(Weight: 30%)* | **D01** | Email Phishing | Credential theft lures via email |
| | **D02** | Social Engineering | Coercion, urgency, and emotional manipulation |
| | **D03** | Spear Phishing | Tailored, targeted attacks referencing personal context |
| | **D04** | Scam & Fraud | Advance-fee fraud, lotteries, and prize scams |
| | **D05** | Smishing | SMS-specific shortlinks and urgent lures |
| | **D06** | Government Scams | Fake IRS, HMRC, police, or court notifications |
| | **D07** | Financial / Investment Fraud | Fake crypto platforms, pump-and-dump, Ponzi schemes |
| | **D08** | Recruitment Scams | Fake work-from-home offers demanding upfront payment |
| | **D09** | Tech Support Scams | Fake virus warnings promoting remote-access tools |
| **Domain 2: Malicious URLs & Domains**<br>*(Weight: 30%)* | **D10** | Malicious URL | High URL risk score, token stacking, bad TLDs |
| | **D11** | Brand Impersonation | Well-known brand names on unauthorized domains |
| | **D12** | Malicious Redirects | Redirect cloaking, `?url=` and `?redirect=` chains |
| | **D13** | URL Obfuscation | Punycode, hex encoding, IP hosts, `@` character tricks |
| | **D14** | IDN / Homograph Attack | Lookalike Unicode characters substituting Latin characters |
| **Domain 3: Web & Credential Security**<br>*(Weight: 20%)* | **D15** | Credential Harvesting | Unauthorized password and payment input fields |
| | **D16** | Fake Auth Pages | Spoofed login screens with external form actions |
| | **D17** | Malicious Webpages | `eval()` execution, drive-by scripts, dangerous iframes |
| **Domain 4: Email Threats**<br>*(Weight: 15%)* | **D18** | Business Email Compromise | From/Reply-To mismatch + urgent financial demands |
| | **D19** | Spam | Bulk unauthenticated emails + high link counts |
| | **D20** | Suspicious Attachments | Double extensions, executable attachments, macros |
| **Domain 5: Media Threats**<br>*(Weight: 5%)* | **D21** | QR Phishing (Quishing) | Malicious links embedded inside QR code images |
| | **D22** | Screenshot Scam | Text extracted via OCR containing active scam lures |

---

## 4. Scoring Mathematics & Verdict Assignment

ThreatSense AI avoids simple arithmetic averaging to prevent safe components from diluting critical dangers.

### Step 1: Per-Domain Amplification (Noisy-OR)
For each domain $k$, the combined score is computed as:
$$\text{DomainScore}_k = 1 - \prod_{i} (1 - S_i)$$
*Where $S_i$ is the individual score of detector $i$ inside domain $k$.*  
* **Effect:** When multiple detectors in the same domain fire, the evidence compounds and drives the domain score toward 1.0.

### Step 2: Weighted Overall Score
$$\text{OverallScore} = \frac{\sum_k (\text{DomainScore}_k \times \text{Weight}_k)}{\sum_k \text{Weight}_k} \times 100$$

### Step 3: Critical Threat Floor Override
If **any single domain** records a critical score ($\text{DomainScore}_k \ge 0.80$), an automatic floor is triggered:
$$\text{FinalRiskScore} = \max(\text{OverallScore}, 70.0)$$
* **Why this matters:** An artifact containing an active credential harvester or a verified phishing domain cannot receive a low score simply because other domains (e.g. Email or Media) were not applicable.

---

## 5. Verdict Thresholds

| Risk Score | Verdict | Meaning | Action Taken |
|:---:|:---:|:---|:---|
| **0 – 24** | `SAFE` | Genuine, benign artifact with no malicious indicators. | Allowed; marked clean. |
| **25 – 49** | `SUSPICIOUS` | Low-to-moderate risk signals (e.g., generic link shorteners, minor urgency). | Proceed with caution. |
| **50 – 74** | `LIKELY_MALICIOUS` | Significant threat detected (e.g., brand impersonation, spoofed headers). | Block and isolate. |
| **75 – 100** | `MALICIOUS` | Critical, confirmed threat (e.g., active credential theft, malicious executable). | Quarantine and alert security team. |

---

*Generated for ThreatSense AI System Documentation.*
