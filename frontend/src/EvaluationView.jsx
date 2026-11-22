import { useState } from 'react'
import {
  NLP_EVAL, NLP_DATASETS, NLP_MODELS, URL_MODEL, METRIC_DEFS, pct, num,
} from './data/evalData'

function IconChart({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 3v18h18" />
      <path d="m7 15 4-6 4 4 5-8" />
    </svg>
  )
}

function IconInfo({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-4M12 8h.01" />
    </svg>
  )
}

function IconLayers({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="12 2 2 7 12 12 22 7 12 2" />
      <polyline points="2 17 12 22 22 17" />
      <polyline points="2 12 12 17 22 12" />
    </svg>
  )
}

// ── Honest status banner ───────────────────────────────────────────────────────

function ProvenanceBanner() {
  return (
    <div className="eval-banner">
      <div className="eval-banner-icon"><IconInfo size={18} /></div>
      <div>
        <div className="eval-banner-title">Evaluation provenance — read before quoting these numbers</div>
        <p>
          The DeBERTa checkpoint was trained on <strong>synthetic bootstrap examples</strong> and is
          <strong> rejected by the backend</strong>, which serves the rules baseline instead. The URL
          model is a <strong>synthetic CI fixture</strong> (100 URLs) and is skipped in production.
          Metrics below are honest measurements of the current artifacts — they are shown to
          demonstrate the evaluation protocol, not production detection accuracy.
        </p>
      </div>
    </div>
  )
}

// ── Confusion Matrix ───────────────────────────────────────────────────────────

function ConfusionMatrix({ m }) {
  const cells = [
    { label: 'TN', value: m.tn, cls: 'tn', hint: 'Benign → cleared' },
    { label: 'FP', value: m.fp, cls: 'fp', hint: 'Benign → flagged' },
    { label: 'FN', value: m.fn, cls: 'fn', hint: 'Threat → missed' },
    { label: 'TP', value: m.tp, cls: 'tp', hint: 'Threat → caught' },
  ]
  const total = m.n || (m.tn + m.fp + m.fn + m.tp) || 1

  return (
    <div className="cm-wrap">
      <div className="cm-axis-label">Actual ▸ / Predicted ▾</div>
      <div className="cm-grid">
        <div className="cm-corner" />
        <div className="cm-col-head">Benign</div>
        <div className="cm-col-head">Threat</div>

        <div className="cm-row-head">Benign</div>
        {cells.slice(0, 2).map((c) => (
          <div key={c.label} className={`cm-cell ${c.cls}`} title={c.hint}>
            <span className="cm-cell-label">{c.label}</span>
            <span className="cm-cell-value">{c.value}</span>
            <span className="cm-cell-pct">{((c.value / total) * 100).toFixed(1)}%</span>
          </div>
        ))}

        <div className="cm-row-head">Threat</div>
        {cells.slice(2).map((c) => (
          <div key={c.label} className={`cm-cell ${c.cls}`} title={c.hint}>
            <span className="cm-cell-label">{c.label}</span>
            <span className="cm-cell-value">{c.value}</span>
            <span className="cm-cell-pct">{((c.value / total) * 100).toFixed(1)}%</span>
          </div>
        ))}
      </div>
      <div className="cm-legend">
        <span><i className="dot tn" /> Correctly cleared</span>
        <span><i className="dot fp" /> False alarms</span>
        <span><i className="dot fn" /> Missed threats</span>
        <span><i className="dot tp" /> Caught threats</span>
      </div>
    </div>
  )
}

// ── Metric card with CI bar ────────────────────────────────────────────────────

function MetricCard({ def, value, ci }) {
  const [hover, setHover] = useState(false)
  const v = value ?? null
  const isRate = ['roc_auc', 'pr_auc', 'f1', 'mcc', 'accuracy', 'balanced_accuracy',
    'precision', 'recall', 'specificity', 'fpr', 'fnr', 'recall_at_1pct_fpr'].includes(def.key)
  // Error/distance metrics: lower is better. Rates: higher is better.
  const lowerBetter = ['fpr', 'fnr', 'brier', 'ece'].includes(def.key)
  const display = isRate ? pct(v) : num(v)
  const barWidth = v == null ? 0 : Math.min(1, Math.max(0, v)) * 100
  const tone = v == null ? 'neutral'
    : lowerBetter ? (v <= 0.05 ? 'good' : v <= 0.2 ? 'warn' : 'bad')
    : v >= 0.9 ? 'good' : v >= 0.7 ? 'ok' : v >= 0.5 ? 'warn' : 'bad'

  return (
    <div
      className={`metric-card tone-${tone}`}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    >
      <div className="metric-card-head">
        <span className="metric-card-label" title={def.desc}>{def.label}</span>
        <span className="metric-card-value">{display}</span>
      </div>
      <div className="metric-bar-track">
        {ci && (hover || !hover) && (
          <div className="metric-ci-band" style={{ left: `${ci[0] * 100}%`, width: `${(ci[1] - ci[0]) * 100}%` }} />
        )}
        <div className={`metric-bar-fill ${tone}`} style={{ width: `${isRate || lowerBetter ? barWidth : 0}%` }} />
      </div>
      {ci ? (
        <div className="metric-ci-text">95% CI [{isRate ? pct(ci[0]) : num(ci[0])} – {isRate ? pct(ci[1]) : num(ci[1])}]</div>
      ) : (
        <div className="metric-ci-text muted">{def.desc.split('—')[0].trim()}</div>
      )}
      <div className="metric-tooltip" hidden={!hover}>{def.desc}</div>
    </div>
  )
}

// ── Model comparison strip ─────────────────────────────────────────────────────

function ModelCompare({ dataset }) {
  const keys = [
    { key: 'roc_auc', label: 'ROC-AUC' },
    { key: 'pr_auc', label: 'PR-AUC' },
    { key: 'f1', label: 'F1' },
    { key: 'mcc', label: 'MCC' },
    { key: 'recall', label: 'Recall' },
    { key: 'fpr', label: 'FPR ↓' },
  ]
  return (
    <div className="eval-compare-table-wrap">
      <table className="eval-compare-table">
        <thead>
          <tr>
            <th>Metric</th>
            {NLP_MODELS.map((m) => <th key={m.id}>{m.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {keys.map((k) => (
            <tr key={k.key}>
              <td className="eval-compare-metric">{k.label}</td>
              {NLP_MODELS.map((m) => {
                const v = NLP_EVAL.models[m.id]?.[dataset]?.[k.key]
                const cls = k.key === 'fpr' || k.key === 'fnr'
                  ? (v <= 0.1 ? 'good' : v <= 0.3 ? 'warn' : 'bad')
                  : (v >= 0.8 ? 'good' : v >= 0.6 ? 'warn' : 'bad')
                return <td key={m.id}><span className={`eval-cell ${cls}`}>{pct(v)}</span></td>
              })}
            </tr>
          ))}
          <tr>
            <td className="eval-compare-metric">Threshold (chosen on val)</td>
            {NLP_MODELS.map((m) => (
              <td key={m.id}>
                <span className="eval-cell neutral">{num(NLP_EVAL.models[m.id]?.[dataset]?.threshold, 3)}</span>
              </td>
            ))}
          </tr>
        </tbody>
      </table>
    </div>
  )
}

// ── NLP dataset detail panel ───────────────────────────────────────────────────

function NlpDatasetPanel({ dataset }) {
  const meta = NLP_EVAL.datasets[dataset]
  const dsDef = NLP_DATASETS.find((d) => d.id === dataset)
  const [model, setModel] = useState('deberta_checkpoint')
  const m = NLP_EVAL.models[model]?.[dataset]

  if (!m) return <div className="eval-empty">No evaluation data for this dataset.</div>

  return (
    <>
      <div className="eval-section-header">
        <div className="eval-section-title-group">
          <div className="eval-icon-pill"><IconChart size={16} /></div>
          <div>
            <div className="eval-section-title">{dsDef.label} — Test Metrics</div>
            <div className="eval-section-sub">{dsDef.desc}</div>
          </div>
        </div>
        <div className="eval-model-switch">
          {NLP_MODELS.map((mm) => (
            <button
              key={mm.id}
              type="button"
              className={`eval-model-tab ${model === mm.id ? 'active' : ''}`}
              onClick={() => setModel(mm.id)}
            >
              {mm.label}
            </button>
          ))}
        </div>
      </div>

      <div className="eval-meta-strip">
        <div className="eval-meta-item">
          <span className="eval-meta-label">Test samples</span>
          <span className="eval-meta-value">{meta.test}</span>
        </div>
        <div className="eval-meta-item">
          <span className="eval-meta-label">Validation samples</span>
          <span className="eval-meta-value">{meta.validation}</span>
        </div>
        <div className="eval-meta-item">
          <span className="eval-meta-label">Threat rate (test)</span>
          <span className="eval-meta-value">{pct(meta.test_positive_rate)}</span>
        </div>
        <div className="eval-meta-item">
          <span className="eval-meta-label">Frozen threshold</span>
          <span className="eval-meta-value">{num(m.threshold, 3)}</span>
        </div>
      </div>

      <div className="eval-metric-grid">
        {METRIC_DEFS.map((def) => (
          <MetricCard
            key={def.key}
            def={def}
            value={m[def.key]}
            ci={m.ci95?.[def.key]}
          />
        ))}
      </div>

      <div className="eval-detail-row">
        <div className="card-section eval-detail-card">
          <div className="card-section-header">
            <div className="card-title-group">
              <div className="card-icon-pill"><IconLayers size={15} /></div>
              <span className="card-title">Confusion Matrix</span>
            </div>
            <span className="panel-title-badge">{m.n} test samples</span>
          </div>
          <ConfusionMatrix m={m} />
        </div>

        <div className="card-section eval-detail-card">
          <div className="card-section-header">
            <div className="card-title-group">
              <div className="card-icon-pill"><IconInfo size={15} /></div>
              <span className="card-title">Fixed Threshold 0.5 (vs. tuned)</span>
            </div>
            <span className="panel-title-badge">Untuned behaviour</span>
          </div>
          <div className="eval-fixed-grid">
            {Object.entries(m['fixed_threshold_0.5']).map(([k, v]) => (
              <div key={k} className="eval-fixed-item">
                <span className="eval-fixed-label">{k.replace(/_/g, ' ')}</span>
                <span className="eval-fixed-value">{pct(v)}</span>
              </div>
            ))}
          </div>
          <p className="eval-note">
            Tuned thresholds are selected on the validation half only, then frozen before touching
            the test half. The fixed-threshold block shows how the same checkpoint behaves with a
            naive 0.5 cutoff — a useful honesty check against threshold overfitting.
          </p>
        </div>
      </div>

      <div className="eval-compare-section">
        <div className="eval-section-title-group">
          <span className="eval-section-title">Head-to-Head — DeBERTa checkpoint vs. Rules baseline</span>
        </div>
        <ModelCompare dataset={dataset} />
      </div>
    </>
  )
}

// ── Latency panel ──────────────────────────────────────────────────────────────

function LatencyPanel() {
  const lat = NLP_EVAL.latency_ms_per_text_batch16
  if (!lat) return null
  const bars = [
    { label: 'p50', value: lat.p50, max: lat.p95 },
    { label: 'mean', value: lat.mean, max: lat.p95 },
    { label: 'p95', value: lat.p95, max: lat.p95 },
  ]
  return (
    <div className="card-section eval-latency-card">
      <div className="card-section-header">
        <div className="card-title-group">
          <div className="card-icon-pill"><IconChart size={15} /></div>
          <span className="card-title">Inference Latency — DeBERTa, batch 16</span>
        </div>
        <span className="panel-title-badge">ms / text</span>
      </div>
      <div className="eval-latency-bars">
        {bars.map((b) => (
          <div key={b.label} className="eval-latency-row">
            <span className="eval-latency-label">{b.label}</span>
            <div className="metric-bar-track">
              <div className="metric-bar-fill ok" style={{ width: `${(b.value / b.max) * 100}%` }} />
            </div>
            <span className="eval-latency-value">{b.value.toFixed(1)} ms</span>
          </div>
        ))}
      </div>
      <p className="eval-note">
        Measured on CPU during the public-corpus scoring run ({NLP_EVAL.datasets
          ? Object.values(NLP_EVAL.datasets).reduce((a, d) => a + d.validation + d.test, 0)
          : 0} texts total).
      </p>
    </div>
  )
}

// ── URL model card ─────────────────────────────────────────────────────────────

function UrlModelCard() {
  const u = URL_MODEL
  const cmTotal = u.confusion.tn + u.confusion.fp + u.confusion.fn + u.confusion.tp
  return (
    <div className="card-section eval-url-card">
      <div className="card-section-header">
        <div className="card-title-group">
          <div className="card-icon-pill"><IconLinkPill /></div>
          <span className="card-title">URL XGBoost Model Card</span>
        </div>
        <span className="eval-status-badge warn">{u.statusLabel}</span>
      </div>

      <div className="eval-url-body">
        <div className="eval-url-metrics">
          {u.metrics.map((mm) => (
            <div key={mm.key} className="eval-fixed-item">
              <span className="eval-fixed-label">{mm.label}</span>
              <span className="eval-fixed-value">{pct(mm.value)}</span>
            </div>
          ))}
          <div className="eval-fixed-item">
            <span className="eval-fixed-label">Median / P99 latency</span>
            <span className="eval-fixed-value">{u.latency.medianMs} / {u.latency.p99Ms} ms</span>
          </div>
          <div className="eval-fixed-item">
            <span className="eval-fixed-label">Latency acceptance</span>
            <span className="eval-fixed-value">{u.latency.acceptance}</span>
          </div>
        </div>

        <div className="eval-url-side">
          <div className="eval-url-facts">
            <div className="eval-meta-item">
              <span className="eval-meta-label">Train / Test (synthetic)</span>
              <span className="eval-meta-value">{u.testSet.train} / {u.testSet.test}</span>
            </div>
            <div className="eval-meta-item">
              <span className="eval-meta-label">Confusion (TN·FP·FN·TP)</span>
              <span className="eval-meta-value">
                {u.confusion.tn}·{u.confusion.fp}·{u.confusion.fn}·{u.confusion.tp} (n={cmTotal})
              </span>
            </div>
          </div>
          <p className="eval-note">{u.statusDetail}</p>
        </div>
      </div>
    </div>
  )
}

function IconLinkPill() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </svg>
  )
}

// ── Main Evaluation View ───────────────────────────────────────────────────────

export default function EvaluationView() {
  const [dataset, setDataset] = useState('sms_spam')

  return (
    <div className="eval-view">
      <ProvenanceBanner />

      {/* Hero summary strip */}
      <div className="eval-hero">
        <div className="eval-hero-item">
          <span className="eval-hero-value">{NLP_MODELS.length + 1}</span>
          <span className="eval-hero-label">Artifacts evaluated</span>
        </div>
        <div className="eval-hero-item">
          <span className="eval-hero-value">
            {Object.values(NLP_EVAL.datasets).reduce((a, d) => a + d.validation + d.test, 0)}
          </span>
          <span className="eval-hero-label">Scored texts (NLP)</span>
        </div>
        <div className="eval-hero-item">
          <span className="eval-hero-value">{METRIC_DEFS.length}+</span>
          <span className="eval-hero-label">Metrics incl. bootstrap 95% CIs</span>
        </div>
        <div className="eval-hero-item">
          <span className="eval-hero-value">0.5 / 0.5</span>
          <span className="eval-hero-label">Validation / test split per dataset</span>
        </div>
      </div>

      {/* Dataset selector */}
      <div className="eval-dataset-tabs">
        {NLP_DATASETS.map((d) => (
          <button
            key={d.id}
            type="button"
            className={`eval-dataset-tab ${dataset === d.id ? 'active' : ''}`}
            onClick={() => setDataset(d.id)}
            title={d.desc}
          >
            {d.label}
          </button>
        ))}
      </div>

      <NlpDatasetPanel dataset={dataset} />

      <LatencyPanel />
      <UrlModelCard />

      {/* Protocol card */}
      <div className="card-section eval-protocol-card">
        <div className="card-section-header">
          <div className="card-title-group">
            <div className="card-icon-pill"><IconInfo size={15} /></div>
            <span className="card-title">Evaluation Protocol</span>
          </div>
        </div>
        <ol className="eval-protocol-list">
          <li><strong>De-duplicate</strong> every corpus and drop texts under 5 characters.</li>
          <li><strong>Stratified sample</strong> per dataset (SMS 3,000 · phishing 2,000 · Enron 2,000).</li>
          <li><strong>Split 50/50</strong> into validation and test halves, stratified by label.</li>
          <li><strong>Threshold selection happens on the validation half only</strong>, maximizing F1; it is then frozen.</li>
          <li><strong>Test metrics</strong> are computed once on the untouched test half.</li>
          <li><strong>Bootstrap 95% CIs</strong> (1,000 resamples, seed 42) quantify uncertainty on key metrics.</li>
          <li>Both models (checkpoint & rules baseline) are scored under the <strong>identical protocol</strong> for a fair comparison.</li>
        </ol>
        <p className="eval-note">
          Public corpora only provide one binary label (threat vs. benign), so the binary view uses
          score = max(phishing_intent, scam_intent). The other 13 NLP signals cannot be evaluated
          without reviewed labels. Full methodology: <code>ml/evaluation/evaluate_nlp_public.py</code>.
        </p>
      </div>
    </div>
  )
}
