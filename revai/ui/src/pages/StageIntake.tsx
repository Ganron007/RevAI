import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getBrowse, stageSample } from '../api/client'
import type { BrowsePayload } from '../api/types'
import { Button, EmptyState, ErrorBanner, Field, Icon, Input, LogBox, Muted, NoteBanner, PageHeader, Panel } from '../ds'

export default function StageIntake() {
  const nav = useNavigate()
  const [src, setSrc] = useState('')
  const [family, setFamily] = useState('')
  const [browse, setBrowse] = useState<BrowsePayload | null>(null)
  const [showBrowse, setShowBrowse] = useState(false)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    void (async () => {
      try {
        setBrowse(await getBrowse())
      } catch {
        /* optional */
      }
    })()
  }, [])

  const openBrowse = async () => {
    setErr(null)
    try {
      setBrowse(await getBrowse())
      setShowBrowse(true)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    }
  }

  const doStage = async () => {
    const path = src.trim()
    if (!path) {
      setErr('Source path on Remnux is required')
      return
    }
    if (path.endsWith('/') || path.endsWith('\\')) {
      setErr('Provide a file path, not a directory')
      return
    }
    setBusy(true)
    setErr(null)
    setMsg('Staging — intake runs on Remnux (can take several minutes; keep this tab open)…')
    try {
      const r = await stageSample(path, family.trim() || 'unknown')
      if (!r.ok || !r.sha256) throw new Error(r.error || 'stage failed')
      setMsg(`Staged ${r.family || family} · ${r.sha256.slice(0, 16)}`)
      nav(`/cases/${r.sha256}/orch`)
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
      setMsg(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="app-main" style={{ overflowY: 'auto' }}>
      <div style={{ maxWidth: 720, margin: '0 auto' }}>
        <PageHeader title="Stage sample" subtitle="copy into corpus + run intake on Remnux" />
        {err && <ErrorBanner>{err}</ErrorBanner>}
        {msg && <NoteBanner>{msg}</NoteBanner>}

        <Panel style={{ marginTop: 'var(--sp-4)' }}>
          <div style={{ display: 'grid', gap: 'var(--sp-3)' }}>
            <Field
              label="Source path on Remnux"
              hint="must be under /opt/samples/incoming or /opt/samples/mta-routing"
            >
              <Input
                value={src}
                onChange={(e) => setSrc(e.target.value)}
                placeholder="/opt/samples/mta-routing/corpus/Family/<sha>/sample.exe"
                className="mono"
                disabled={busy}
                onKeyDown={(e) => e.key === 'Enter' && void doStage()}
              />
            </Field>
            <Field label="Family / project name">
              <Input
                value={family}
                onChange={(e) => setFamily(e.target.value)}
                placeholder="SnakeKeylogger"
                disabled={busy}
              />
            </Field>
            <div className="toolbar" style={{ marginBottom: 0 }}>
              <Button onClick={() => void openBrowse()} disabled={busy} icon={<Icon.evidence size={13} />}>
                Browse
              </Button>
              <span className="spacer" />
              <Button tone="primary" onClick={() => void doStage()} disabled={busy} icon={<Icon.stage size={13} />}>
                {busy ? 'Staging…' : 'Stage'}
              </Button>
            </div>
          </div>
        </Panel>

        {showBrowse && (
          <Panel
            title="Browse Remnux dirs"
            actions={
              <Button size="sm" tone="ghost" icon={<Icon.close size={12} />} onClick={() => setShowBrowse(false)}>
                Close
              </Button>
            }
            style={{ marginTop: 'var(--sp-4)' }}
          >
            {browse?.upload?.note && (
              <div style={{ marginBottom: 'var(--sp-3)', fontSize: 'var(--tx-sm)' }}>
                <div style={{ color: 'var(--accent-hi)', fontWeight: 600 }}>
                  Dropbox: {browse.upload.dropbox || '—'}
                </div>
                <div className="muted">{browse.upload.note}</div>
              </div>
            )}
            {!browse?.dirs?.length ? (
              <EmptyState title="No browse dirs" detail="Check Remnux sample paths" />
            ) : (
              <div style={{ display: 'grid', gap: 'var(--sp-3)' }}>
                {browse.dirs.map((d) => {
                  const files = d.files.filter((f) => !f.is_dir)
                  return (
                    <div key={d.path}>
                      <div className="mono" style={{ marginBottom: 6, color: 'var(--tx-2)', fontSize: 'var(--tx-xs)' }}>
                        {d.path} ({files.length} files)
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {files.map((f) => (
                          <Button
                            key={f.name}
                            size="sm"
                            tone="ghost"
                            onClick={() => {
                              setSrc(`${d.path.replace(/\/$/, '')}/${f.name}`)
                              setShowBrowse(false)
                            }}
                          >
                            <span className="mono">{f.name}</span>
                          </Button>
                        ))}
                        {!files.length && <Muted>No files</Muted>}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
            {browse?.upload?.commands && (
              <div style={{ marginTop: 'var(--sp-3)' }}>
                <LogBox>
                  {Object.entries(browse.upload.commands)
                    .map(([k, v]) => `${k}: ${v}`)
                    .join('\n')}
                </LogBox>
              </div>
            )}
          </Panel>
        )}
      </div>
    </div>
  )
}
