import { useEffect, useMemo, useRef, useState } from 'react'
import { orchTrace } from '../../api/client'
import { STAGE_LABELS, STAGE_ORDER } from '../../api/schema'
import { Badge, Button, EmptyState, Icon, Kpi, Panel, SourceBadge } from '../../ds'
import { useCase } from '../../pages/caseContext'
import type { OrchLive } from '../../api/types'

type Tool = NonNullable<OrchLive['tools']>[number]

function lightState(
  tools: Tool[],
  stageName: string,
  running: boolean,
  currentTool?: string | null,
  currentStage?: string | null,
): 'idle' | 'done' | 'run' | 'err' {
  if (running && (currentStage === stageName || (currentTool && toolStageKey(currentTool) === stageName))) {
    return 'run'
  }
  const hits = tools.filter((t) => {
    const st = (t.stage || toolStageKey(t.tool)).toLowerCase()
    return st === stageName || (t.tool || '').includes(stageName)
  })
  const last = hits[hits.length - 1]
  if (!last) return 'idle'
  if (last.status === 'running') return 'run'
  if (last.status === 'error' || last.status === 'failed') return 'err'
  if (last.rc === 0 || last.status === 'ok' || last.status === 'done') return 'done'
  if (last.rc != null && last.rc !== 0) return 'err'
  return 'idle'
}

function toolStageKey(tool?: string | null) {
  const t = (tool || '').replace(/^run_/, '').replace(/_agentic$/, '')
  if (t === 'section_publish' || t === 'section') return 'correlate'
  if (t === 'quick') return 'quick_scan'
  if (t === 'yara') return 'yara_gen'
  return t
}

function fmtDur(s?: number | null) {
  if (s == null) return ''
  if (s < 60) return `${s.toFixed(1)}s`
  return `${Math.floor(s / 60)}m${Math.round(s % 60).toString().padStart(2, '0')}s`
}

/* ── Stage timeline ─────────────────────────────────────────────────── */
function StageTimeline({
  tools,
  running,
  currentTool,
  currentStage,
  onJump,
}: {
  tools: Tool[]
  running: boolean
  currentTool?: string | null
  currentStage?: string | null
  onJump: (stage: string) => void
}) {
  const stages = [...STAGE_ORDER, 'check_quality']
  const total = tools.reduce((acc, t) => acc + (t.duration_s || 0), 0) || 1
  return (
    <div className="timeline">
      {stages.map((s) => {
        const st = lightState(tools, s, running, currentTool, currentStage)
        const dur = tools
          .filter((t) => (t.stage || toolStageKey(t.tool)) === s)
          .reduce((acc, t) => acc + (t.duration_s || 0), 0)
        const flexGrow = Math.max(1, Math.round((dur / total) * 10))
        return (
          <div
            key={s}
            className={`tl-seg ${st}`}
            style={{ flexGrow }}
            onClick={() => onJump(s)}
            data-tip={`${STAGE_LABELS[s] || s}${dur ? ` · ${fmtDur(dur)}` : ''}`}
          >
            <div className="name">{STAGE_LABELS[s] || s}</div>
            <div className="meta">{dur ? fmtDur(dur) : st === 'run' ? '…' : '—'}</div>
          </div>
        )
      })}
    </div>
  )
}

/* ── Agent trace tree ───────────────────────────────────────────────── */
function TraceTree({ tools, highlightStage }: { tools: Tool[]; highlightStage?: string | null }) {
  const [open, setOpen] = useState<Record<string, boolean>>(() => {
    const init: Record<string, boolean> = {}
    for (const t of tools) {
      const st = t.status === 'error' || t.status === 'failed' || (t.rc != null && t.rc !== 0)
      if (st) init[t.tool || ''] = true
    }
    return init
  })

  useEffect(() => {
    if (highlightStage) setOpen((o) => ({ ...o, [highlightStage]: true }))
  }, [highlightStage])

  // Group by outer stage tool (run_*) — nested events under deep dive
  const outer = tools.filter((t) => (t.tool || '').startsWith('run_') || (t.tool || '') === 'read_verdicts')
  const nested = tools.filter((t) => !outer.includes(t))

  const rowCls = (t: Tool) => {
    if (t.status === 'running') return 'run'
    if (t.status === 'error' || t.status === 'failed' || (t.rc != null && t.rc !== 0)) return 'err'
    return 'ok'
  }

  const renderRow = (t: Tool, idx: number, child = false) => {
    const name = t.tool || `tool-${idx}`
    const expandable = !child && nested.length > 0 && name === 'run_deep_dive_agentic'
    const isOpen = open[name] ?? false
    return (
      <div key={`${name}-${idx}`}>
        <div
          className={`trace-row ${rowCls(t)}`}
          onClick={() => expandable && setOpen((o) => ({ ...o, [name]: !isOpen }))}
          style={child ? { paddingLeft: 8 } : undefined}
        >
          {expandable ? (
            <span className={`trace-chev${isOpen ? ' open' : ''}`}>
              <Icon.chevron size={12} />
            </span>
          ) : (
            <span style={{ width: 14 }} />
          )}
          <span className="tname">{name}</span>
          <span className="tmeta">
            <span>{t.status || (t.rc === 0 ? 'ok' : '—')}</span>
            <span>rc={t.rc ?? '—'}</span>
            <span>{fmtDur(t.duration_s)}</span>
          </span>
        </div>
        {expandable && isOpen && (
          <div className="trace-children">
            {nested.map((n, i) => renderRow(n, i, true))}
            {nested.length === 0 && <div className="muted" style={{ padding: 4 }}>no nested events captured</div>}
          </div>
        )}
      </div>
    )
  }

  if (!tools.length) return <EmptyState title="No tool events yet" detail="Run the orchestrator to populate the trace" />
  return <div className="trace">{outer.length ? outer.map((t, i) => renderRow(t, i)) : tools.map((t, i) => renderRow(t, i))}</div>
}

/* ── Live console ───────────────────────────────────────────────────── */
function LiveConsole({ live }: { live: OrchLive | null }) {
  const ref = useRef<HTMLPreElement>(null)
  const [paused, setPaused] = useState(false)
  const file = live?.log_tail || []
  const task = live?.task_log_tail || []
  const lines = file.length ? file : task
  const text = lines.join('\n') || '(empty — waiting for orchestrator output)'

  useEffect(() => {
    if (!paused && ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [text, paused])

  return (
    <>
      <div className="console-toolbar">
        <Badge tone={live?.running ? 'run' : 'default'} pulse={!!live?.running}>
          {live?.running ? 'LIVE' : 'static'}
        </Badge>
        <span className="muted" style={{ fontSize: 'var(--tx-xs)' }}>
          {lines.length} lines
        </span>
        <span className="spacer" style={{ marginLeft: 'auto' }} />
        <Button size="sm" tone="ghost" onClick={() => setPaused((p) => !p)} icon={paused ? <Icon.play size={12} /> : <Icon.pause size={12} />}>
          {paused ? 'Resume' : 'Pause'}
        </Button>
      </div>
      <pre ref={ref} className="console" onMouseEnter={() => live?.running && setPaused(true)}>
        {text}
      </pre>
    </>
  )
}

/* ── Quality gate bar ───────────────────────────────────────────────── */
function QualityBar({ live }: { live: OrchLive | null }) {
  const issues = live?.quality_issues || []
  const checks = live?.quality_checks || {}
  const green = live?.quality_green
  return (
    <div className={`qgate ${green ? 'green' : green === false ? 'red' : ''}`}>
      <Badge tone={green ? 'ok' : green === false ? 'danger' : 'default'}>
        {green ? 'QUALITY GATE GREEN' : green === false ? 'QUALITY GATE FAIL' : 'NO GATE DATA'}
      </Badge>
      {checks &&
        Object.entries(checks)
          .filter(([, v]) => v && typeof v === 'object' && 'source' in v)
          .map(([k, v]) => (
            <span key={k} className="qgate-item">
              <span className="muted">{k}</span>
              <SourceBadge source={v.source} />
              {v.chars != null && <span className="mono" style={{ fontSize: 'var(--tx-xs)' }}>{Math.round(v.chars / 1000)}k</span>}
            </span>
          ))}
      {issues.length > 0 && (
        <span className="qgate-item" style={{ color: 'var(--danger)' }}>
          <Icon.alert size={13} /> {issues.length} issue{issues.length === 1 ? '' : 's'}
        </span>
      )}
    </div>
  )
}

/* ── Main ───────────────────────────────────────────────────────────── */
export default function OrchCommandCenter() {
  const { sha, live, refreshLive, mode: runMode } = useCase()
  const [, setTrace] = useState<Record<string, unknown> | null>(null)
  const [jumpStage, setJumpStage] = useState<string | null>(null)

  useEffect(() => {
    if (!sha || live?.running || !live?.artifacts?.orchestrator_trace) return
    let cancelled = false
    void orchTrace(sha, runMode)
      .then((t) => {
        if (!cancelled) setTrace(t)
      })
      .catch(() => {
        if (!cancelled) setTrace(null)
      })
    return () => {
      cancelled = true
    }
  }, [sha, runMode, live?.running, live?.artifacts?.orchestrator_trace])

  const tools = useMemo(() => live?.tools || [], [live?.tools])
  const deep = live?.deep || {}
  const currentTool = live?.current_tool || (typeof live?.current === 'string' ? live.current : null)
  const currentStage = live?.current_stage || null

  return (
    <div>
      <div className="kpi-strip">
        <Kpi
          label="truly_green"
          value={live?.truly_green == null ? '—' : live.truly_green ? 'true' : 'FALSE'}
          tone={live?.truly_green ? 'ok' : live?.truly_green === false ? 'danger' : undefined}
          tip="all_green + quality gate + zero failed tools"
        />
        <Kpi
          label="quality"
          value={live?.quality_green == null ? '—' : live?.quality_green ? 'green' : 'FAIL'}
          tone={live?.quality_green ? 'ok' : live?.quality_green === false ? 'warn' : undefined}
        />
        <Kpi
          label="deep tools"
          value={
            Array.isArray(deep.successful_tool_calls)
              ? deep.successful_tool_calls.length
              : typeof deep.successful_tool_calls === 'number'
                ? deep.successful_tool_calls
                : '—'
          }
          tone="info"
          tip="successful tool calls inside nested LangGraph deep dive"
        />
        <Kpi
          label="deep gates"
          value={`${deep.checklist_ok ? '✓' : '·'}${deep.sql_deep_ok ? '✓' : '·'}`}
          tone={deep.checklist_ok && deep.sql_deep_ok ? 'ok' : undefined}
          tip={`checklist_ok=${String(deep.checklist_ok)} sql_deep_ok=${String(deep.sql_deep_ok)}`}
        />
        <Kpi label="engine" value={deep.engine || '—'} tone="accent" />
        <Kpi
          label="elapsed"
          value={live?.elapsed_s != null ? fmtDur(live.elapsed_s) : '—'}
        />
        <span style={{ marginLeft: 'auto', alignSelf: 'center' }}>
          <Button size="sm" tone="ghost" icon={<Icon.refresh size={12} />} onClick={() => void refreshLive()}>
            Refresh
          </Button>
        </span>
      </div>

      <Panel title="Stage timeline" style={{ marginBottom: 'var(--sp-4)' }}>
        <StageTimeline
          tools={tools}
          running={!!live?.running}
          currentTool={currentTool}
          currentStage={currentStage}
          onJump={(s) => setJumpStage(s)}
        />
      </Panel>

      <div className="split-55" style={{ marginBottom: 'var(--sp-4)' }}>
        <Panel title="Agent trace">
          <TraceTree tools={tools} highlightStage={jumpStage} />
        </Panel>
        <Panel title="Live console">
          <LiveConsole live={live} />
        </Panel>
      </div>

      <QualityBar live={live} />
    </div>
  )
}
