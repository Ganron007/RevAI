import { useState } from 'react'
import { Badge, Button, verdictTone } from '../ds'
import type { OrchLive, Sample } from '../api/types'
import { useCase } from '../pages/caseContext'

function fmtElapsed(s?: number | null) {
  if (s == null) return null
  const m = Math.floor(s / 60)
  const sec = Math.round(s % 60)
  return m > 0 ? `${m}m${sec.toString().padStart(2, '0')}s` : `${sec}s`
}

export default function CaseChrome({
  sha,
  sample,
  live,
  hitlCount,
  busy,
  onRun,
  onStop,
}: {
  sha: string
  sample: Sample | null
  live: OrchLive | null
  hitlCount: number
  busy: boolean
  onRun: () => void
  onStop: () => void
}) {
  let ctxMode: string | null = null
  let ctxModes: string[] = []
  let ctxSetMode: ((m: string | null) => void) | null = null
  try {
    const ctx = useCase()
    ctxMode = ctx.mode ?? null
    ctxModes = ctx.modes ?? []
    ctxSetMode = ctx.setMode ?? null
  } catch {
    /* outside CaseWorkspace — no tabs */
  }
  const [copied, setCopied] = useState(false)
  const title = sample?.display_name || sample?.sha_short || sha.slice(0, 12)
  const elapsed = fmtElapsed(live?.elapsed_s)
  const stagesDone = (live?.stages_run || []).length

  const copySha = async () => {
    try {
      await navigator.clipboard.writeText(sha)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1200)
    } catch {
      /* clipboard unavailable */
    }
  }

  return (
    <div className="case-head">
      <div className="row1">
        <h1>{title}</h1>
        <span className="sha" data-tip={copied ? 'copied' : 'copy full sha256'} onClick={() => void copySha()}>
          {copied ? 'copied ✓' : `${sha.slice(0, 16)}…`}
        </span>
        {sample?.family_guess && <Badge tone="accent">{sample.family_guess}</Badge>}
        <Badge tone={verdictTone(sample?.verdict)}>
          {sample?.verdict || 'unknown'}
          {sample?.score != null ? ` ${sample.score}` : ''}
        </Badge>
        <Badge tone={live?.running ? 'run' : live?.truly_green ? 'ok' : live?.truly_green === false ? 'danger' : 'default'} pulse={!!live?.running}>
          {live?.running ? 'RUNNING' : live?.truly_green ? 'truly_green' : live?.truly_green === false ? 'GATE FAIL' : live?.status || 'idle'}
        </Badge>
        {hitlCount > 0 && <Badge tone="warn">HITL {hitlCount}</Badge>}
        <div className="actions">
          <Button tone="primary" disabled={busy || !!live?.running} onClick={onRun}>
            Run orch
          </Button>
          <Button tone="danger" disabled={busy || !live?.running} onClick={onStop}>
            Stop
          </Button>
        </div>
      </div>
      <div className="row2">
        <span>
          stages <b>{stagesDone > 0 ? `${stagesDone}/7` : '—'}</b>
        </span>
        {elapsed && (
          <span>
            elapsed <b>{elapsed}</b>
          </span>
        )}
        {live?.planner_model && (
          <span>
            planner <b className="mono">{live.planner_model}</b>
          </span>
        )}
        {live?.judgment_model && (
          <span>
            judgment <b className="mono">{live.judgment_model}</b>
          </span>
        )}
        {sample?.pipeline_mode && (
          <span>
            mode <b>{sample.pipeline_mode}</b>
          </span>
        )}
      </div>
      {ctxModes.length > 0 && ctxSetMode && (
        <div className="mode-tabs" style={{ display: 'flex', gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
          {ctxModes.map((m) => (
            <button
              key={m}
              className={`mode-tab${ctxMode === m ? ' active' : ''}`}
              onClick={() => ctxSetMode!(m)}
              style={{
                padding: '4px 10px',
                borderRadius: 6,
                border: ctxMode === m ? '1px solid var(--accent)' : '1px solid var(--line)',
                background: ctxMode === m ? 'var(--accent-wash)' : 'var(--bg-2)',
                color: ctxMode === m ? 'var(--accent-hi)' : 'var(--tx-1)',
                fontWeight: ctxMode === m ? 600 : 400,
                cursor: 'pointer',
                fontSize: 12,
              }}
            >
              {m}
            </button>
          ))}
          <button
            className={`mode-tab${ctxMode === null ? ' active' : ''}`}
            onClick={() => ctxSetMode!(null)}
            title="legacy flat dir (pre-segregation)"
            style={{
              padding: '4px 10px',
              borderRadius: 6,
              border: ctxMode === null ? '1px solid var(--accent)' : '1px solid var(--line)',
              background: ctxMode === null ? 'var(--accent-wash)' : 'var(--bg-2)',
              color: ctxMode === null ? 'var(--accent-hi)' : 'var(--tx-1)',
              fontWeight: ctxMode === null ? 600 : 400,
              cursor: 'pointer',
              fontSize: 12,
            }}
          >
            legacy
          </button>
        </div>
      )}
    </div>
  )
}
