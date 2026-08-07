import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getPipelineMap, getSamples, orchActive } from '../api/client'
import type { PipelineMap, Sample } from '../api/types'
import { Badge, Dot, Icon, verdictTone } from '../ds'
import { LogoMark } from '../ds/Logo'

function ageOf(iso?: string | null): string {
  if (!iso) return '—'
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return '—'
  const mins = Math.max(0, Math.round((Date.now() - t) / 60000))
  if (mins < 60) return `${mins}m ago`
  const h = Math.floor(mins / 60)
  if (h < 48) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export default function LandingPage() {
  const nav = useNavigate()
  const [samples, setSamples] = useState<Sample[]>([])
  const [running, setRunning] = useState<Set<string>>(new Set())
  const [pmap, setPmap] = useState<PipelineMap | null>(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [s, a, pm] = await Promise.all([getSamples(), orchActive(), getPipelineMap()])
        if (cancelled) return
        setSamples(s)
        setRunning(new Set((a.active || []).map((x) => x.sha).filter(Boolean)))
        setPmap(pm)
      } catch {
        /* landing degrades gracefully */
      }
    }
    void load()
    const id = window.setInterval(() => void load(), 8000)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [])

  const malicious = samples.filter((s) => (s.verdict || '').toLowerCase().includes('malicious')).length
  const recent = [...samples]
    .sort((a, b) => Date.parse(b.staged_at || '') - Date.parse(a.staged_at || ''))
    .slice(0, 5)

  return (
    <div className="landing-bg">
      <div className="landing-inner">
        <div className="landing-grid">
          {/* ── Left: brand + pathways ── */}
          <div>
            <div className="reveal">
              <span className="landing-eyebrow">
                <Icon.evidence size={12} /> Malware Reverse-Engineering Lab
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <LogoMark size={56} />
                <h1 className="landing-title" style={{ margin: 0 }}>
                  CADRE<span style={{ color: 'var(--tx-2)', fontWeight: 400 }}>//</span>
                  <span className="accent">RevAI</span>
                </h1>
              </div>
              <p className="landing-sub">
                A deterministic malware-analysis pipeline with an agentic deep-dive loop. Stage a
                binary, and the console drives intake → triage → deep reverse-engineering → detection
                rules → reporting, gating every run on evidence quality — not just a green light.
              </p>
            </div>

            <div className="reveal d1">
              <button className="pathway primary" onClick={() => nav('/stage')}>
                <span className="pathway-icon">
                  <Icon.stage size={18} />
                </span>
                <span className="pathway-body">
                  <span className="pathway-title">Analyze a new sample</span>
                  <span className="pathway-desc">
                    SCP the binary to the dropbox, stage it, and run the full LangGraph pipeline.
                  </span>
                </span>
                <span className="pathway-arrow">→</span>
              </button>

              <button className="pathway" onClick={() => nav('/cases')}>
                <span className="pathway-icon">
                  <Icon.cases size={18} />
                </span>
                <span className="pathway-body">
                  <span className="pathway-title">Review existing analyses</span>
                  <span className="pathway-desc">
                    Browse staged cases, reopen any run, and inspect its reports, evidence and audit trail.
                  </span>
                </span>
                <span className="pathway-arrow">→</span>
              </button>

              <button className="pathway" onClick={() => nav('/help')}>
                <span className="pathway-icon">
                  <Icon.reports size={18} />
                </span>
                <span className="pathway-body">
                  <span className="pathway-title">How the pipeline works</span>
                  <span className="pathway-desc">
                    The seven stages (plus the optional function-recovery stage), the quality gates
                    (including the depth gate), verdicts, and how to read a run.
                  </span>
                </span>
                <span className="pathway-arrow">→</span>
              </button>
            </div>
          </div>

          {/* ── Right: live status board ── */}
          <div>
            <div className="board reveal d2">
              <div className="board-head">
                <Dot state={running.size ? 'live' : 'ok'} />
                <h3>Lab status</h3>
                <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 'var(--tx-xs)', color: 'var(--tx-2)' }}>
                  {pmap?.product_mode || 'LLM-only · static RE'}
                </span>
              </div>
              <div className="board-body">
                <div className="board-stats">
                  <Stat label="Cases staged" value={samples.length} />
                  <Stat label="Running now" value={running.size} tone={running.size ? 'info' : undefined} live={running.size > 0} />
                  <Stat label="Malicious" value={malicious} tone={malicious ? 'danger' : undefined} />
                  <Stat label="Pipeline stages" value={pmap?.stages.length ?? 7} tone="accent" />
                </div>
              </div>
            </div>

            <div className="board reveal d3">
              <div className="board-head">
                <h3>Recent analyses</h3>
                <a
                  style={{ marginLeft: 'auto', fontSize: 'var(--tx-xs)', color: 'var(--accent-hi)' }}
                  onClick={() => nav('/cases')}
                >
                  view all →
                </a>
              </div>
              <div className="board-body" style={{ padding: 'var(--sp-2)' }}>
                {recent.length === 0 && (
                  <div style={{ padding: 'var(--sp-3)', color: 'var(--tx-2)', fontSize: 'var(--tx-sm)' }}>
                    No cases yet — stage your first sample.
                  </div>
                )}
                {recent.map((s) => (
                  <div key={s.sha256} className="recent-row" onClick={() => nav(`/cases/${s.sha256}/orch`)}>
                    <Dot state={running.has(s.sha256) ? 'live' : 'idle'} />
                    <span className="nm">{s.display_name || s.sha256.slice(0, 12)}</span>
                    <Badge tone={verdictTone(s.verdict)}>{s.verdict || 'unknown'}</Badge>
                    <span className="meta">{ageOf(s.staged_at)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── Pipeline strip ── */}
        <div className="landing-section-label reveal d4">
          <h2>The analysis pipeline</h2>
          <span className="rule" />
          <a onClick={() => nav('/help')}>full documentation →</a>
        </div>
        <div className="pipe-strip reveal d4">
          {(pmap?.stages || []).map((st, i) => (
            <div key={st.id} className="pstage" onClick={() => nav('/help')} data-tip={st.script || st.id}>
              <div className="pstage-num">{String(i + 1).padStart(2, '0')}</div>
              <div className="pstage-label">{st.label}</div>
              <div className="pstage-desc">{st.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function Stat({
  label,
  value,
  tone,
  live,
}: {
  label: string
  value: number
  tone?: 'info' | 'danger' | 'accent'
  live?: boolean
}) {
  const color =
    tone === 'info' ? 'var(--info)' : tone === 'danger' ? 'var(--danger)' : tone === 'accent' ? 'var(--accent-hi)' : 'var(--tx-0)'
  return (
    <div>
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--tx-2xl)',
          fontWeight: 500,
          color,
          fontVariantNumeric: 'tabular-nums',
          lineHeight: 1.1,
        }}
      >
        {value}
        {live && <span style={{ fontSize: '0.5em', verticalAlign: 'super' }}> ●</span>}
      </div>
      <div style={{ fontSize: 'var(--tx-xs)', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--tx-2)' }}>
        {label}
      </div>
    </div>
  )
}
