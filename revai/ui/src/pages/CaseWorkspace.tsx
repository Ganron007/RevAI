import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { NavLink, Outlet, useParams } from 'react-router-dom'
import { getHitlPending, getModes, getSamples, orchLive, orchStart, orchStop } from '../api/client'
import type { OrchLive, Sample } from '../api/types'
import { ErrorBanner, Icon } from '../ds'
import CaseChrome from '../layout/CaseChrome'
import { CaseContext } from './caseContext'

export { useCase } from './caseContext'

const RAIL = [
  { to: 'orch', label: 'Orchestrator', icon: <Icon.orch /> },
  { to: 'reports', label: 'Reports', icon: <Icon.reports /> },
  { to: 'evidence', label: 'Evidence', icon: <Icon.evidence /> },
  { to: 'review', label: 'HITL Review', icon: <Icon.hitl /> },
  { to: 'manual', label: 'Manual Stages', icon: <Icon.manual /> },
] as const

export default function CaseWorkspace() {
  const { sha = '' } = useParams()
  const [sample, setSample] = useState<Sample | null>(null)
  const [live, setLive] = useState<OrchLive | null>(null)
  const [hitlCount, setHitlCount] = useState(0)
  const [err, setErr] = useState<string | null>(null)
  const [pollErr, setPollErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const [modes, setModes] = useState<string[]>([])
  const [mode, setMode] = useState<string | null>(null)
  const runningRef = useRef(false)
  const failCount = useRef(0)

  const refreshLive = useCallback(async () => {
    if (!sha) return
    const l = await orchLive(sha, mode)
    setLive(l)
    runningRef.current = !!l.running
  }, [sha, mode])

  const refreshHitl = useCallback(async () => {
    if (!sha) return
    try {
      const hitl = await getHitlPending(sha)
      setHitlCount(hitl.pending_count || 0)
    } catch {
      /* ignore */
    }
  }, [sha])

  useEffect(() => {
    if (!sha) return
    setSample(null)
    setLive(null)
    setHitlCount(0)
    setErr(null)
    setPollErr(null)
    setModes([])
    setMode(null)
    runningRef.current = false
    failCount.current = 0
    let cancelled = false
    ;(async () => {
      try {
        const [samples, hitl, m] = await Promise.all([getSamples(), getHitlPending(sha), getModes(sha).catch(() => [] as string[])])
        if (cancelled) return
        setSample(samples.find((s) => s.sha256 === sha) || null)
        setHitlCount(hitl.pending_count || 0)
        setModes(m)
        // prefer agentic > scripted > ui > legacy (null)
        if (m.length) {
          const pref = ['agentic', 'scripted', 'ui']
          const pick = pref.find((p) => m.includes(p)) ?? m[0]
          setMode(pick)
        } else {
          setMode(null)
        }
      } catch (e) {
        if (!cancelled) setErr(e instanceof Error ? e.message : String(e))
      }
    })()
    return () => {
      cancelled = true
    }
  }, [sha])

  useEffect(() => {
    if (!sha) return
    let timer: number | undefined
    let stopped = false
    const tick = async () => {
      try {
        await refreshLive()
        failCount.current = 0
        setPollErr(null)
      } catch (e) {
        failCount.current += 1
        if (failCount.current >= 3) {
          setPollErr(e instanceof Error ? e.message : 'orch poll failed')
        }
      }
      if (stopped) return
      const ms = runningRef.current ? 1500 : 8000
      timer = window.setTimeout(() => void tick(), ms)
    }
    void tick()
    return () => {
      stopped = true
      if (timer) window.clearTimeout(timer)
    }
  }, [sha, refreshLive])

  // refresh when mode switches
  useEffect(() => {
    if (sha) void refreshLive().catch(() => undefined)
  }, [mode, refreshLive, sha])

  const onRun = async () => {
    setBusy(true)
    setErr(null)
    try {
      const r = await orchStart(sha)
      if (!r.ok) throw new Error(r.error || 'start failed')
      runningRef.current = true
      await refreshLive()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const onStop = async () => {
    setBusy(true)
    try {
      await orchStop(sha)
      await refreshLive()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const ctx = useMemo(
    () => ({ sha, sample, live, refreshLive, refreshHitl, mode, modes, setMode }),
    [sha, sample, live, refreshLive, refreshHitl, mode, modes],
  )

  return (
    <CaseContext.Provider value={ctx}>
      <aside className={`rail${collapsed ? ' collapsed' : ''}`}>
        <button className="rail-toggle" onClick={() => setCollapsed((v) => !v)} data-tip={collapsed ? 'expand' : 'collapse'}>
          <Icon.panelLeft />
        </button>
        <div className="rail-section">
          <div className="rail-label">Case</div>
          {RAIL.map((r) => (
            <NavLink
              key={r.to}
              to={`/cases/${sha}/${r.to}`}
              className={({ isActive }) => `rail-item${isActive ? ' active' : ''}`}
              data-tip={collapsed ? r.label : undefined}
            >
              {r.icon}
              <span className="txt">{r.label}</span>
              {r.to === 'review' && hitlCount > 0 && <span className="count">{hitlCount}</span>}
            </NavLink>
          ))}
        </div>
        <div className="rail-section" style={{ marginTop: 'auto' }}>
          <NavLink to="/" className="rail-item" data-tip={collapsed ? 'All cases' : undefined}>
            <Icon.cases />
            <span className="txt">All cases</span>
          </NavLink>
        </div>
      </aside>
      <main className="app-main">
        {(err || pollErr) && <ErrorBanner>{err || pollErr}</ErrorBanner>}
        <CaseChrome
          sha={sha}
          sample={sample}
          live={live}
          hitlCount={hitlCount}
          busy={busy}
          onRun={() => void onRun()}
          onStop={() => void onStop()}
        />
        <Outlet />
      </main>
    </CaseContext.Provider>
  )
}
