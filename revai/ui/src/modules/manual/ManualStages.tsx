import { useCallback, useEffect, useState } from 'react'
import { getStatus, getTask, runStage } from '../../api/client'
import { STAGE_LABELS, STAGE_ORDER } from '../../api/schema'
import { Badge, Button, ErrorBanner, Icon, LogBox, Muted, Panel } from '../../ds'
import { useCase } from '../../pages/caseContext'

export default function ManualStages() {
  const { sha } = useCase()
  const [stages, setStages] = useState<Record<string, { status?: string }>>({})
  const [busy, setBusy] = useState<string | null>(null)
  const [log, setLog] = useState('')
  const [err, setErr] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    const st = await getStatus(sha)
    setStages((st.stages as Record<string, { status?: string }>) || {})
  }, [sha])

  useEffect(() => {
    void refresh().catch(() => undefined)
  }, [refresh])

  const run = async (stage: string) => {
    setBusy(stage)
    setErr(null)
    setLog(`Starting ${stage}…`)
    try {
      const { task_id } = await runStage(sha, stage)
      for (let i = 0; i < 7200; i++) {
        await new Promise((r) => setTimeout(r, 1500))
        const t = await getTask(task_id)
        const tail = t.log_tail || (t as { log?: string[] }).log || []
        setLog(tail.join('\n') || t.status)
        if (t.status === 'done' || t.status === 'error' || t.status === 'failed') {
          if (t.returncode != null && t.returncode !== 0) setErr(`${stage} rc=${t.returncode}`)
          break
        }
      }
      await refresh()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div>
      <Muted>
        Script-path single-stage runner. Prefer the Orchestrator for the full LangGraph spine.
      </Muted>
      {err && <ErrorBanner>{err}</ErrorBanner>}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(170px, 1fr))', gap: 'var(--sp-3)', marginTop: 'var(--sp-4)' }}>
        {STAGE_ORDER.map((s) => {
          const st = stages[s]?.status || 'idle'
          const done = st === 'done' || st === 'done-inferred'
          return (
            <div key={s} className="panel" style={{ padding: 'var(--sp-3)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <h4 style={{ fontSize: 'var(--tx-sm)', fontWeight: 600 }}>{STAGE_LABELS[s]}</h4>
                <Badge tone={done ? 'ok' : st === 'running' ? 'run' : 'default'} pulse={st === 'running'}>
                  {st}
                </Badge>
              </div>
              <Button size="sm" disabled={!!busy} icon={<Icon.play size={12} />} onClick={() => void run(s)}>
                {busy === s ? 'Running…' : 'Run'}
              </Button>
            </div>
          )
        })}
      </div>
      <Panel title="Stage log" style={{ marginTop: 'var(--sp-4)' }}>
        <LogBox>{log || '(idle)'}</LogBox>
      </Panel>
    </div>
  )
}
