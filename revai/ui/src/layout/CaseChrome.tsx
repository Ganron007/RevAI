import { useState } from 'react'
import { Badge, Button, verdictTone } from '../ds'
import type { OrchLive, Sample } from '../api/types'

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
    </div>
  )
}
