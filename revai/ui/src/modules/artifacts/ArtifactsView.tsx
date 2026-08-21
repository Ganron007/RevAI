import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { getEvidence, getFileText, getReports } from '../../api/client'
import type { EvidenceFile } from '../../api/types'
import { Badge, EmptyState, ErrorBanner, Icon, Muted, Seg, Select, Toolbar } from '../../ds'
import { useCase } from '../../pages/caseContext'
import { DocumentPreview } from './DocumentPreview'

function fmtSize(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function basename(path: string) {
  return path.split('/').pop() || path
}

function findByCanon(list: EvidenceFile[], names: string[]) {
  for (const n of names) {
    const hit = list.find((f) => basename(f.path) === n || (f as { canon_name?: string }).canon_name === n)
    if (hit) return hit
  }
  return undefined
}

export default function ArtifactsView({ initialMode = 'reports' }: { initialMode?: 'reports' | 'evidence' }) {
  const { sha, mode: runMode } = useCase()
  const [mode, setMode] = useState<'evidence' | 'reports'>(initialMode)
  const [internals, setInternals] = useState(false)
  const [viewMode, setViewMode] = useState<'rendered' | 'raw'>('rendered')
  const [files, setFiles] = useState<EvidenceFile[]>([])
  const [stageFilter, setStageFilter] = useState('all')
  const [sel, setSel] = useState<string | null>(null)
  const [text, setText] = useState('')
  const [loadingFile, setLoadingFile] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const seqRef = useRef(0)

  const loadFile = useCallback(
    async (path: string) => {
      abortRef.current?.abort()
      const ac = new AbortController()
      abortRef.current = ac
      const seq = ++seqRef.current
      setSel(path)
      setLoadingFile(true)
      try {
        const t = await getFileText(sha, path, runMode)
        if (ac.signal.aborted || seq !== seqRef.current) return
        setText(t.length > 800_000 ? `${t.slice(0, 800_000)}\n\n… truncated for preview` : t)
        setViewMode(/\.(md|markdown)$/i.test(path) ? 'rendered' : 'raw')
      } catch (e) {
        if (ac.signal.aborted || seq !== seqRef.current) return
        setText(e instanceof Error ? e.message : String(e))
        setViewMode('raw')
      } finally {
        if (seq === seqRef.current) setLoadingFile(false)
      }
    },
    [sha, runMode],
  )

  useEffect(() => {
    let cancelled = false
    void (async () => {
      setErr(null)
      setSel(null)
      setText('')
      try {
        const list = mode === 'reports' ? await getReports(sha, internals, runMode) : await getEvidence(sha, runMode)
        if (cancelled) return
        setFiles(list)
        if (mode === 'reports' && list.length) {
          const prefer =
            findByCanon(list, ['REPORT-MASTER-v3.md', 'REPORT-MASTER-v2.md', 'REPORT-MASTER.md']) ||
            list.find((f) => /REPORT-MASTER/i.test(basename(f.path))) ||
            findByCanon(list, ['REPORT-TECHNICAL-v3.md', 'REPORT-TECHNICAL-v2.md']) ||
            list.find((f) => /REPORT-TECHNICAL/i.test(basename(f.path))) ||
            list[0]
          if (prefer) await loadFile(prefer.path)
        }
      } catch (e) {
        if (!cancelled) {
          setErr(e instanceof Error ? e.message : String(e))
          setFiles([])
        }
      }
    })()
    return () => {
      cancelled = true
      abortRef.current?.abort()
    }
  }, [sha, mode, internals, runMode, loadFile])

  const stages = useMemo(() => {
    const s = new Set(files.map((f) => f.stage))
    return ['all', ...Array.from(s).sort()]
  }, [files])

  const visible = useMemo(() => {
    if (mode === 'reports' || stageFilter === 'all') return files
    return files.filter((f) => f.stage === stageFilter)
  }, [files, mode, stageFilter])

  return (
    <div>
      {err && <ErrorBanner>{err}</ErrorBanner>}
      <Toolbar>
        <Seg<'reports' | 'evidence'>
          value={mode}
          onChange={setMode}
          options={[
            ['reports', 'Reports'],
            ['evidence', 'Evidence'],
          ]}
        />
        {mode === 'reports' && (
          <label className="muted" style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 'var(--tx-sm)' }}>
            <input type="checkbox" checked={internals} onChange={(e) => setInternals(e.target.checked)} />
            internals
          </label>
        )}
        {mode === 'evidence' && (
          <Select value={stageFilter} onChange={(e) => setStageFilter(e.target.value)}>
            {stages.map((s) => (
              <option key={s} value={s}>
                {s === 'all' ? 'all stages' : s}
              </option>
            ))}
          </Select>
        )}
        <Seg<'rendered' | 'raw'>
          value={viewMode}
          onChange={setViewMode}
          options={[
            ['rendered', 'Rendered'],
            ['raw', 'Raw'],
          ]}
        />
        <Muted>
          {visible.length} file{visible.length === 1 ? '' : 's'}
        </Muted>
        {sel && (
          <a
            href={`/api/download/${sha}?path=${encodeURIComponent(sel)}${runMode ? `&mode=${encodeURIComponent(runMode)}` : ''}`}
            style={{ marginLeft: 'auto', display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 'var(--tx-sm)', fontWeight: 500 }}
            download
          >
            <Icon.download size={13} /> Download
          </a>
        )}
      </Toolbar>

      <div className="reader-layout">
        <div className="reader-list panel" style={{ padding: 8 }}>
          {!visible.length ? (
            <EmptyState title="No files" detail={mode === 'reports' ? 'Run publish/section first' : undefined} />
          ) : (
            visible.map((f) => (
              <div
                key={f.path}
                className={`reader-item${sel === f.path ? ' active' : ''}`}
                onClick={() => void loadFile(f.path)}
              >
                <span className="nm mono">{basename(f.path)}</span>
                <span className="mt">
                  {f.kind && <Badge tone="info">{f.kind}</Badge>}
                  <span>{fmtSize(f.size)}</span>
                </span>
              </div>
            ))
          )}
        </div>
        <div style={{ minWidth: 0 }}>
          {!sel ? (
            <div className="panel">
              <EmptyState title="Select a document" detail="MASTER / TECHNICAL / AUDIT render with a section outline" />
            </div>
          ) : (
            <DocumentPreview path={sel} text={text} mode={viewMode} loading={loadingFile} />
          )}
        </div>
      </div>
    </div>
  )
}
