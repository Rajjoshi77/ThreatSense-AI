import { useState, useRef, useCallback, useEffect } from 'react'

// ── Constants & Configuration ──────────────────────────────────────────────────

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

const ARTIFACT_TYPES = [
  { id: 'url',     label: 'URL',      binary: false, desc: 'Analyze links, phishing redirects & homoglyphs' },
  { id: 'email',   label: 'Email',    binary: false, desc: 'Analyze RFC 822 headers, spoofing & content' },
  { id: 'sms',     label: 'SMS / Chat', binary: false, desc: 'Analyze smishing, urgency patterns & scams' },
  { id: 'webpage', label: 'Webpage',  binary: true,  desc: 'Inspect raw HTML, DOM scripts & forms' },
  { id: 'image',   label: 'Image',    binary: true,  desc: 'Detect hidden steganography & visual threats' },
  { id: 'qr',      label: 'QR Code',  binary: true,  desc: 'Decode quishing & embedded malicious payloads' },
  { id: 'file',    label: 'File',     binary: true,  desc: 'Analyze file metadata, PE headers & macros' },
]

const SAMPLE_PRESETS = [
  {
    type: 'url',
    title: 'PayPal Credential Phishing URL',
    tag: 'malicious',
    tagLabel: 'Phishing',
    content: 'http://secure-paypal-login.xyz/verify?token=abc12345&redirect=account-recovery',
  },
  {
    type: 'sms',
    title: 'Urgent Banking Smishing SMS',
    tag: 'malicious',
    tagLabel: 'Smishing',
    content: 'URGENT: Your SBI account #8921 is temporarily blocked due to suspicious activity. Verify your identity immediately at http://sbi-secure.xyz to avoid suspension.',
  },
  {
    type: 'email',
    title: 'CEO Fraud / Spear-Phishing Wire Request',
    tag: 'suspicious',
    tagLabel: 'BEC Fraud',
    content: `From: "Executive Office" <ceo@corp-internal-update.biz>
To: finance@yourcompany.com
Subject: URGENT: Confidential Wire Transfer Request - Acquisition
Date: Fri, 20 Nov 2026 09:30:00 +0000

Hi Team,

I am in an executive board meeting with poor reception. Please process an urgent wire transfer of $48,500 to our external counsel today.
Details are attached. Treat this with strict confidentiality.

Regards,
Chief Executive Officer`,
  },
  {
    type: 'sms',
    title: 'Safe Operational Notification (Baseline)',
    tag: 'safe',
    tagLabel: 'Benign',
    content: 'Hello Team, your scheduled code review meeting is set for tomorrow at 10:00 AM UTC in Conference Room B. See you there.',
  },
]

const SEV_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

// ── SVG Icon System ────────────────────────────────────────────────────────────

function IconShield({ className, size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  )
}

function IconCheckShield({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>
  )
}

function IconAlertTriangle({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
      <line x1="12" y1="9" x2="12" y2="13"/>
      <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  )
}

function IconAlertOctagon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>
  )
}

function IconLink({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
    </svg>
  )
}

function IconMail({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect width="20" height="16" x="2" y="4" rx="2"/>
      <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
    </svg>
  )
}

function IconMessage({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/>
    </svg>
  )
}

function IconGlobe({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="2" y1="12" x2="22" y2="12"/>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  )
}

function IconImage({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect width="18" height="18" x="3" y="3" rx="2" ry="2"/>
      <circle cx="9" cy="9" r="2"/>
      <path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/>
    </svg>
  )
}

function IconQr({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect width="5" height="5" x="3" y="3" rx="1"/>
      <rect width="5" height="5" x="16" y="3" rx="1"/>
      <rect width="5" height="5" x="3" y="16" rx="1"/>
      <path d="M21 16h-3a2 2 0 0 0-2 2v3"/>
      <path d="M21 21v.01"/>
      <path d="M12 7v3a2 2 0 0 1-2 2H7"/>
      <path d="M3 12h.01"/>
      <path d="M12 3h.01"/>
      <path d="M12 16v.01"/>
      <path d="M16 12h1"/>
      <path d="M21 12v.01"/>
      <path d="M12 21v-1"/>
    </svg>
  )
}

function IconFile({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
      <polyline points="14 2 14 8 20 8"/>
    </svg>
  )
}

function IconCopy({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
      <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
    </svg>
  )
}

function IconCheck({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  )
}

function IconTrash({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 6h18"/>
      <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
      <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>
    </svg>
  )
}

function IconDownload({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
      <polyline points="7 10 12 15 17 10"/>
      <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
  )
}

function IconRefresh({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/>
      <path d="M21 3v5h-5"/>
      <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/>
      <path d="M3 21v-5h5"/>
    </svg>
  )
}

function renderTypeIcon(type, size = 18) {
  switch (type) {
    case 'url':     return <IconLink size={size} />
    case 'email':   return <IconMail size={size} />
    case 'sms':     return <IconMessage size={size} />
    case 'webpage': return <IconGlobe size={size} />
    case 'image':   return <IconImage size={size} />
    case 'qr':      return <IconQr size={size} />
    case 'file':    return <IconFile size={size} />
    default:        return <IconFile size={size} />
  }
}

// ── Color Utilities ────────────────────────────────────────────────────────────

function getRiskColor(score) {
  if (score >= 75) return '#dc2626' // Critical
  if (score >= 50) return '#ea580c' // High
  if (score >= 25) return '#d97706' // Medium
  return '#059669'                 // Safe
}

function getDomainColor(val) {
  if (val >= 0.75) return '#dc2626'
  if (val >= 0.50) return '#ea580c'
  if (val >= 0.25) return '#d97706'
  return '#059669'
}

// ── Score Ring Component ───────────────────────────────────────────────────────

function ScoreRing({ score }) {
  const r = 38
  const circ = 2 * Math.PI * r
  const clamped = Math.max(0, Math.min(100, score || 0))
  const dash = (clamped / 100) * circ
  const color = getRiskColor(clamped)

  return (
    <div className="score-ring">
      <svg width="96" height="96" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="#e2e8f0" strokeWidth="8" />
        <circle
          cx="50"
          cy="50"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 1s cubic-bezier(0.16, 1, 0.3, 1)' }}
        />
      </svg>
      <div className="score-center">
        <span className="score-num">{Math.round(clamped)}</span>
        <span className="score-label">Risk Score</span>
      </div>
    </div>
  )
}

// ── Verdict Badge ──────────────────────────────────────────────────────────────

function VerdictBadge({ verdict }) {
  const v = verdict?.toLowerCase() || 'unknown'
  const icons = {
    malicious: <IconAlertOctagon size={14} />,
    likely_malicious: <IconAlertTriangle size={14} />,
    suspicious: <IconAlertTriangle size={14} />,
    safe: <IconCheckShield size={14} />,
    unknown: <IconShield size={14} />,
  }

  return (
    <span className={`verdict-badge ${v}`}>
      {icons[v] || <IconShield size={14} />}
      {v.replace('_', ' ')}
    </span>
  )
}

// ── Domain Breakdown ───────────────────────────────────────────────────────────

function DomainBreakdown({ domains }) {
  if (!domains?.length) return null

  return (
    <div className="card-section">
      <div className="card-section-header">
        <div className="card-title-group">
          <div className="card-icon-pill">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
              <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
              <line x1="12" y1="22.08" x2="12" y2="12"/>
            </svg>
          </div>
          <span className="card-title">Threat Domain Vector Breakdown</span>
        </div>
        <span className="panel-title-badge">5 Domains</span>
      </div>

      <div className="domain-grid">
        {domains.map((d) => {
          const scorePercent = (d.score * 100).toFixed(0)
          const barColor = getDomainColor(d.score)

          return (
            <div className="domain-row" key={d.domain_id}>
              <div className="domain-name">{d.domain_name}</div>
              <div className="domain-bar-bg">
                <div
                  className="domain-bar-fill"
                  style={{
                    width: `${(d.score * 100).toFixed(1)}%`,
                    backgroundColor: barColor,
                  }}
                />
              </div>
              <div className="domain-score" style={{ color: barColor }}>
                {scorePercent}%
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Evidence Item ──────────────────────────────────────────────────────────────

function EvidenceItem({ ev }) {
  const sev = ev.severity?.toLowerCase() || 'info'
  const [copied, setCopied] = useState(false)

  const handleCopyText = (text) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="evidence-card">
      <div className={`sev-dot ${sev}`} title={`Severity: ${sev}`} />
      <div className="evidence-body">
        <div className="evidence-header-line">
          <div className="evidence-desc">{ev.description}</div>
          <span className={`sev-badge ${sev}`}>{sev}</span>
        </div>

        <div className="evidence-meta">
          {ev.source_engine && (
            <span className="code-pill">Engine: {ev.source_engine}</span>
          )}
          {ev.rule_id && (
            <span className="code-pill">Rule: {ev.rule_id}</span>
          )}
          {ev.matched_text && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, maxWidth: '100%' }}>
              <span className="matched-snippet" title={ev.matched_text}>
                &ldquo;{ev.matched_text}&rdquo;
              </span>
              <button
                type="button"
                className="copy-btn"
                onClick={() => handleCopyText(ev.matched_text)}
                title="Copy matched payload string"
              >
                {copied ? <IconCheck size={11} /> : <IconCopy size={11} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main ThreatSense App ───────────────────────────────────────────────────────

export default function App() {
  const [artifactType, setArtifactType] = useState('url')
  const [content, setContent] = useState('')
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [loadingStep, setLoadingStep] = useState(1)
  const [error, setError] = useState(null)
  const [report, setReport] = useState(null)
  const [drag, setDrag] = useState(false)
  const [copiedId, setCopiedId] = useState(false)
  const fileRef = useRef(null)

  const activeTypeObj = ARTIFACT_TYPES.find(t => t.id === artifactType) || ARTIFACT_TYPES[0]
  const isBinary = activeTypeObj.binary

  // Cycle loading steps during active scan
  useEffect(() => {
    let interval = null
    if (loading) {
      setLoadingStep(1)
      interval = setInterval(() => {
        setLoadingStep((prev) => (prev < 3 ? prev + 1 : 1))
      }, 900)
    } else {
      setLoadingStep(1)
    }
    return () => clearInterval(interval)
  }, [loading])

  const handleTypeChange = (id) => {
    setArtifactType(id)
    setContent('')
    setFile(null)
    setError(null)
  }

  const handleFileSelect = (f) => {
    if (!f) return
    setFile(f)
    setError(null)
  }

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setDrag(false)
    const droppedFile = e.dataTransfer.files[0]
    if (droppedFile) {
      handleFileSelect(droppedFile)
    }
  }, [])

  const applyPreset = (preset) => {
    setArtifactType(preset.type)
    setContent(preset.content)
    setFile(null)
    setError(null)
    setReport(null)
  }

  const handleCopyAnalysisId = (id) => {
    if (!id) return
    navigator.clipboard.writeText(id)
    setCopiedId(true)
    setTimeout(() => setCopiedId(false), 2000)
  }

  const handleExportJson = () => {
    if (!report) return
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `threatsense-report-${report.analysis_id || 'scan'}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleReset = () => {
    setContent('')
    setFile(null)
    setError(null)
    setReport(null)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setLoading(true)
    setReport(null)

    try {
      let resp
      if (isBinary && file) {
        const fd = new FormData()
        fd.append('type', artifactType)
        fd.append('file', file)
        resp = await fetch(`${API_BASE}/analyze`, { method: 'POST', body: fd })
      } else {
        resp = await fetch(`${API_BASE}/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: artifactType, raw_content: content }),
        })
      }

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }))
        throw new Error(err.detail || `HTTP Error ${resp.status}`)
      }

      const data = await resp.json()
      setReport(data)
    } catch (err) {
      if (err.message.includes('Failed to fetch') || err.message.includes('Network Error')) {
        setError(
          `Connection Error: Could not reach ThreatSense backend at ${API_BASE}.\n\n` +
          `• Verify your FastAPI server is running (e.g. uvicorn app.main:app --reload).\n` +
          `• For remote environments, ensure CORS allows this origin and VITE_API_URL is configured correctly.`
        )
      } else {
        setError(err.message)
      }
    } finally {
      setLoading(false)
    }
  }

  const sortedEvidence = report?.top_evidence
    ? [...report.top_evidence].sort((a, b) =>
        (SEV_ORDER[b.severity?.toLowerCase()] || 0) - (SEV_ORDER[a.severity?.toLowerCase()] || 0)
      )
    : []

  return (
    <div className="app">
      {/* ── Executive Header ── */}
      <header className="header">
        <div className="header-brand">
          <div className="header-logo-icon">
            <IconShield size={22} />
          </div>
          <div className="header-brand-title">
            <h1>ThreatSense AI</h1>
            <span className="header-brand-subtitle">
              Enterprise Cybersecurity Intelligence & Multi-Layer Threat Detection
            </span>
          </div>
        </div>

        <div className="header-right">
          <div className="status-pill">
            <span className="status-dot" />
            <span>Engines Online</span>
          </div>
          <span className="badge-detectors">22 Active Detectors</span>
        </div>
      </header>

      {/* ── Main Workspace ── */}
      <div className="main">
        {/* ── Left Panel: Controls & Input ── */}
        <aside className="panel-left">
          <div className="panel-title">
            <span>Analyze Artifact</span>
            <span className="panel-title-badge">{activeTypeObj.label} Mode</span>
          </div>

          {/* Artifact Type Switcher */}
          <div className="type-selector-wrapper">
            <div className="input-label">
              <span>Select Ingestion Vector</span>
              <span className="input-label-hint">7 Vector Types</span>
            </div>
            <div className="type-grid">
              {ARTIFACT_TYPES.map((t) => (
                <button
                  type="button"
                  key={t.id}
                  className={`type-btn ${artifactType === t.id ? 'active' : ''}`}
                  onClick={() => handleTypeChange(t.id)}
                  title={t.desc}
                >
                  {renderTypeIcon(t.id, 18)}
                  <span>{t.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="input-group">
            {isBinary ? (
              <div className="input-wrapper">
                <div className="input-label">
                  <span>Upload Suspicious {activeTypeObj.label}</span>
                  <span className="input-label-hint">Max 10MB</span>
                </div>

                <div
                  className={`file-drop ${drag ? 'drag-over' : ''}`}
                  onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
                  onDragLeave={() => setDrag(false)}
                  onDrop={handleDrop}
                  onClick={() => fileRef.current?.click()}
                >
                  <input
                    ref={fileRef}
                    type="file"
                    onChange={(e) => handleFileSelect(e.target.files[0])}
                    style={{ display: 'none' }}
                  />

                  {file ? (
                    <div className="file-selected-box" onClick={(e) => e.stopPropagation()}>
                      <div className="file-selected-info">
                        <IconCheckShield size={24} />
                        <div>
                          <div className="file-selected-name">{file.name}</div>
                          <div className="file-selected-meta">
                            {(file.size / 1024).toFixed(1)} KB · {file.type || 'Unknown MIME'}
                          </div>
                        </div>
                      </div>
                      <button
                        type="button"
                        className="file-remove-btn"
                        onClick={() => setFile(null)}
                      >
                        Remove
                      </button>
                    </div>
                  ) : (
                    <>
                      <div className="file-drop-icon">
                        {renderTypeIcon(artifactType, 22)}
                      </div>
                      <div className="file-drop-title">
                        Drag and drop {activeTypeObj.label.toLowerCase()} or click to browse
                      </div>
                      <div className="file-drop-hint">
                        Supports PNG, JPG, WebP, HTML, EML, PDF & binary files
                      </div>
                    </>
                  )}
                </div>
              </div>
            ) : (
              <div className="input-wrapper">
                <div className="input-label">
                  <span>
                    {artifactType === 'url' ? 'Target URL string' :
                     artifactType === 'email' ? 'RFC 822 Email Body (EML headers)' :
                     'SMS or message content'}
                  </span>
                  {content.length > 0 && (
                    <span className="input-label-hint">{content.length} characters</span>
                  )}
                </div>

                <textarea
                  rows={artifactType === 'email' ? 11 : 4}
                  placeholder={
                    artifactType === 'url' ? 'https://example.com/login-verify?token=...' :
                    artifactType === 'email' ? 'From: sender@bank-support.com\nTo: recipient@corp.com\nSubject: Account Verification Required\n\nPlease update your credentials...' :
                    'Paste SMS message, OTP request, or smishing text…'
                  }
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                />

                <div className="input-footer">
                  <span>{activeTypeObj.desc}</span>
                  {content.length > 0 && (
                    <button
                      type="button"
                      className="clear-btn"
                      onClick={() => setContent('')}
                    >
                      <IconTrash size={12} /> Clear
                    </button>
                  )}
                </div>
              </div>
            )}

            <button
              type="submit"
              className="submit-btn"
              disabled={loading || (isBinary ? !file : !content.trim())}
            >
              {loading ? (
                <>
                  <div className="btn-spinner" />
                  <span>Scanning Threat Vectors…</span>
                </>
              ) : (
                <>
                  <IconShield size={16} />
                  <span>Execute Threat Analysis</span>
                </>
              )}
            </button>
          </form>

          {/* Quick-fill sample presets */}
          <div className="preset-section">
            <div className="preset-title">
              <IconCheckShield size={14} />
              <span>Sample Test Vectors</span>
            </div>
            <div className="preset-list">
              {SAMPLE_PRESETS.map((sample, idx) => (
                <div
                  key={idx}
                  className="preset-chip"
                  onClick={() => applyPreset(sample)}
                  title="Click to populate input with this sample"
                >
                  <span>{sample.title}</span>
                  <span className={`preset-chip-tag ${sample.tag}`}>
                    {sample.tagLabel}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </aside>

        {/* ── Right Panel: Results & Diagnostics ── */}
        <main className="panel-right">
          {/* Error Banner */}
          {error && (
            <div className="error-banner">
              <IconAlertOctagon size={24} />
              <div>
                <div className="error-title">Analysis Request Failed</div>
                <div className="error-body">{error}</div>
              </div>
            </div>
          )}

          {/* Idle Placeholder */}
          {!report && !loading && !error && (
            <div className="placeholder-card">
              <div className="placeholder-icon-wrap">
                <IconShield size={32} />
              </div>
              <div className="placeholder-title">Awaiting Threat Artifact</div>
              <p className="placeholder-desc">
                Select an ingestion vector from the left sidebar and provide an artifact (URL, raw email, message, image, or file) to execute multi-layered inspection across 22 detectors.
              </p>
              <div className="detector-badges-row">
                <span className="detector-pill">NLP Threat Engine</span>
                <span className="detector-pill">Homoglyph & URL Heuristics</span>
                <span className="detector-pill">DKIM / SPF Email Forensics</span>
                <span className="detector-pill">DOM & Form Exploits</span>
                <span className="detector-pill">Steganography & QR Decoder</span>
              </div>
            </div>
          )}

          {/* Active Loading Experience with Stage Progression */}
          {loading && (
            <div className="loading-card">
              <div className="loading-header">
                <div className="loading-radar">
                  <IconShield size={24} />
                </div>
                <div>
                  <div className="loading-title">Scanning Across 22 Security Detectors</div>
                  <div className="loading-subtitle">
                    Cross-referencing NLP heuristics, URL engines & domain risk scoring
                  </div>
                </div>
              </div>

              <div className="scanning-steps">
                <div className={`scanning-step-item ${loadingStep >= 1 ? 'active' : ''}`}>
                  <div className="step-indicator">{loadingStep > 1 ? '✓' : '1'}</div>
                  <span>Phase 1: Ingesting payload & normalizing metadata</span>
                </div>
                <div className={`scanning-step-item ${loadingStep >= 2 ? 'active' : ''}`}>
                  <div className="step-indicator">{loadingStep > 2 ? '✓' : '2'}</div>
                  <span>Phase 2: Executing NLP sentiment, homoglyphs & heuristic engines</span>
                </div>
                <div className={`scanning-step-item ${loadingStep >= 3 ? 'active' : ''}`}>
                  <div className="step-indicator">3</div>
                  <span>Phase 3: Aggregating 5 domain risk vectors & calculating verdict</span>
                </div>
              </div>

              {/* Shimmer Skeletons */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div className="skeleton-box" style={{ width: '40%' }} />
                <div className="skeleton-box" style={{ width: '85%' }} />
                <div className="skeleton-box" style={{ width: '65%' }} />
              </div>
            </div>
          )}

          {/* Complete Report Output */}
          {report && !loading && (
            <div className="results-container">
              {/* Executive Summary Card */}
              <div className={`executive-summary-card ${report.verdict?.toLowerCase() || 'unknown'}`}>
                <div className="summary-main">
                  <ScoreRing score={report.risk_score} />
                  <div className="verdict-info">
                    <VerdictBadge verdict={report.verdict} />
                    <div className="primary-threat">
                      {report.primary_threat_type || 'General Cyber Threat Vector'}
                    </div>

                    <div className="threat-meta-row">
                      <span className="meta-item">
                        Confidence: <strong>{((report.confidence || 0) * 100).toFixed(0)}%</strong>
                      </span>
                      <span className="meta-item">
                        NLP Backend: <strong>{report.nlp_backend_used || 'Heuristic Rules'}</strong>
                      </span>
                    </div>

                    {report.secondary_tags?.length > 0 && (
                      <div className="tag-row">
                        {report.secondary_tags.map((tag) => (
                          <span key={tag} className="threat-tag">
                            #{tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'flex-end' }}>
                  <button
                    type="button"
                    className="copy-btn"
                    onClick={handleExportJson}
                    title="Export report as JSON"
                  >
                    <IconDownload size={12} /> Export JSON
                  </button>
                  <button
                    type="button"
                    className="copy-btn"
                    onClick={handleReset}
                    title="Start fresh scan"
                  >
                    <IconRefresh size={12} /> New Scan
                  </button>
                </div>
              </div>

              {/* Domain Breakdown */}
              <DomainBreakdown domains={report.per_domain_scores} />

              {/* Evidence Section */}
              {sortedEvidence.length > 0 && (
                <div className="card-section">
                  <div className="card-section-header">
                    <div className="card-title-group">
                      <div className="card-icon-pill">
                        <IconAlertTriangle size={16} />
                      </div>
                      <span className="card-title">Top Security Evidence ({sortedEvidence.length})</span>
                    </div>
                    <span className="panel-title-badge">Ranked by Severity</span>
                  </div>

                  <div className="evidence-list">
                    {sortedEvidence.map((ev, i) => (
                      <EvidenceItem key={i} ev={ev} />
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Actions */}
              {report.recommended_actions?.length > 0 && (
                <div className="card-section">
                  <div className="card-section-header">
                    <div className="card-title-group">
                      <div className="card-icon-pill">
                        <IconCheckShield size={16} />
                      </div>
                      <span className="card-title">Recommended Incident Response Actions</span>
                    </div>
                  </div>

                  <div className="actions-list">
                    {report.recommended_actions.map((act, i) => (
                      <div key={i} className="action-item">
                        <span className="action-icon">→</span>
                        <span>{act}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Pipeline Diagnostics & Metadata */}
              <div className="metadata-card">
                <div className="metadata-grid">
                  <div className="metadata-box">
                    <span className="metadata-label">Analysis Identifier</span>
                    <div className="metadata-value">
                      <span>{report.analysis_id || 'LOCAL-EXEC-001'}</span>
                      <button
                        type="button"
                        className="copy-btn"
                        onClick={() => handleCopyAnalysisId(report.analysis_id)}
                      >
                        {copiedId ? <IconCheck size={11} /> : <IconCopy size={11} />}
                        {copiedId ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>

                  <div className="metadata-box">
                    <span className="metadata-label">Detector Coverage</span>
                    <div className="metadata-value">
                      <span>22 Total Detectors Registered</span>
                    </div>
                  </div>

                  {report.skipped_components?.length > 0 && (
                    <div className="metadata-box">
                      <span className="metadata-label">Inactive Components</span>
                      <div className="metadata-value" style={{ color: 'var(--text-muted)' }}>
                        {report.skipped_components.length} skipped for artifact type
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
