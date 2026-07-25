import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from '@tanstack/react-table'
import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getSamples, orchActive } from '../api/client'
import type { Sample } from '../api/types'
import {
  Badge,
  Button,
  Dot,
  EmptyState,
  ErrorBanner,
  Input,
  Kpi,
  PageHeader,
  Seg,
  Skeleton,
  Toolbar,
  verdictTone,
} from '../ds'

const col = createColumnHelper<Sample & { orch_running?: boolean }>()

type VerdictFilter = '' | 'malicious' | 'suspicious' | 'benign' | 'unknown'

function ageOf(iso?: string | null): string {
  if (!iso) return '—'
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return '—'
  const mins = Math.max(0, Math.round((Date.now() - t) / 60000))
  if (mins < 60) return `${mins}m`
  const h = Math.floor(mins / 60)
  if (h < 48) return `${h}h`
  return `${Math.floor(h / 24)}d`
}

export default function CasesHub() {
  const nav = useNavigate()
  const [rows, setRows] = useState<Array<Sample & { orch_running?: boolean }>>([])
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')
  const [verdict, setVerdict] = useState<VerdictFilter>('')
  const [sorting, setSorting] = useState<SortingState>([{ id: 'staged_at', desc: true }])
  const [selIdx, setSelIdx] = useState(-1)

  const load = async (soft = false) => {
    if (!soft) setLoading(true)
    setErr(null)
    try {
      const [samples, active] = await Promise.all([getSamples(), orchActive()])
      const running = new Set((active.active || []).map((a) => a.sha).filter(Boolean))
      setRows(samples.map((s) => ({ ...s, orch_running: running.has(s.sha256) })))
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
    const id = window.setInterval(() => void load(true), 8000)
    return () => window.clearInterval(id)
  }, [])

  const filtered = useMemo(() => {
    let list = rows
    if (verdict) {
      list = list.filter((r) => (r.verdict || 'unknown').toLowerCase().includes(verdict))
    }
    return list
  }, [rows, verdict])

  const runningCount = rows.filter((r) => r.orch_running).length
  const maliciousCount = rows.filter((r) => (r.verdict || '').toLowerCase().includes('malicious')).length
  const hitlCount = 0 // HITL badge per case; hub keeps scope to queue health

  const columns = useMemo(
    () => [
      col.accessor((r) => (r.orch_running ? 'live' : 'idle'), {
        id: 'status',
        header: '',
        cell: (i) => <Dot state={i.getValue() === 'live' ? 'live' : 'idle'} tip={i.getValue() === 'live' ? 'orchestrator running' : 'idle'} />,
        size: 40,
      }),
      col.accessor((r) => r.display_name || r.sha_short || r.sha256.slice(0, 12), {
        id: 'display_name',
        header: 'Sample',
        cell: (i) => (
          <span style={{ fontWeight: 600, color: 'var(--tx-0)' }}>{i.getValue()}</span>
        ),
      }),
      col.accessor((r) => r.sha_short || r.sha256.slice(0, 12), {
        id: 'sha_short',
        header: 'SHA-256',
        cell: (i) => <span className="mono">{i.getValue()}</span>,
      }),
      col.accessor((r) => r.family_guess || r.project_name || '', {
        id: 'family',
        header: 'Family',
        cell: (i) => i.getValue() || <span className="muted">—</span>,
      }),
      col.accessor('verdict', {
        header: 'Verdict',
        cell: (i) => <Badge tone={verdictTone(i.getValue())}>{i.getValue() || 'unknown'}</Badge>,
      }),
      col.accessor('score', {
        header: 'Score',
        cell: (i) => <span className="num">{i.getValue() != null ? String(i.getValue()) : '—'}</span>,
      }),
      col.accessor('group', {
        header: 'Group',
        cell: (i) => i.getValue() || <span className="muted">—</span>,
      }),
      col.accessor('staged_at', {
        header: 'Age',
        cell: (i) => <span className="num">{ageOf(i.getValue())}</span>,
      }),
    ],
    [],
  )

  const table = useReactTable({
    data: filtered,
    columns,
    state: { sorting, globalFilter: filter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  })

  const visibleRows = table.getRowModel().rows

  // j/k keyboard navigation
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (e.key === 'j') {
        setSelIdx((v) => Math.min(v + 1, visibleRows.length - 1))
      } else if (e.key === 'k') {
        setSelIdx((v) => Math.max(v - 1, 0))
      } else if (e.key === 'Enter' && selIdx >= 0 && visibleRows[selIdx]) {
        nav(`/cases/${visibleRows[selIdx].original.sha256}/orch`)
      } else if (e.key === 'r' && !e.ctrlKey && !e.metaKey) {
        void load(true)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [visibleRows, selIdx, nav])

  return (
    <div className="app-main" style={{ overflowY: 'auto' }}>
      <PageHeader
        title="Cases"
        subtitle="stage → orchestrate → review · gate on truly_green"
        actions={
          <Button tone="primary" onClick={() => nav('/stage')}>
            Stage sample
          </Button>
        }
      />

      <div className="kpi-strip">
        <Kpi label="Cases" value={rows.length} />
        <Kpi label="Running" value={runningCount} tone={runningCount ? 'info' : undefined} />
        <Kpi label="Malicious" value={maliciousCount} tone={maliciousCount ? 'danger' : undefined} />
        <Kpi label="HITL pending" value={hitlCount} tone={hitlCount ? 'warn' : undefined} />
        <Kpi label="Shown" value={visibleRows.length} />
      </div>

      {err && <ErrorBanner>{err}</ErrorBanner>}

      <Toolbar>
        <Seg<VerdictFilter>
          value={verdict}
          onChange={setVerdict}
          options={[
            ['', 'All'],
            ['malicious', 'Malicious'],
            ['suspicious', 'Suspicious'],
            ['benign', 'Benign'],
            ['unknown', 'Unknown'],
          ]}
        />
        <Input
          placeholder="Filter name / family / sha…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ minWidth: 240 }}
        />
        <span className="spacer" />
        <span className="muted" style={{ fontSize: 'var(--tx-xs)' }}>
          <kbd className="mono">j/k</kbd> navigate · <kbd className="mono">Enter</kbd> open · <kbd className="mono">r</kbd> refresh
        </span>
      </Toolbar>

      {loading && !rows.length ? (
        <Skeleton height={280} />
      ) : visibleRows.length === 0 ? (
        <EmptyState title="No matching cases" detail="Clear filters or stage a sample" />
      ) : (
        <div className="table-wrap">
          <table className="dt">
            <thead>
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id}>
                  {hg.headers.map((h) => (
                    <th
                      key={h.id}
                      onClick={h.column.getToggleSortingHandler()}
                      className={h.column.getCanSort() ? 'sortable' : ''}
                    >
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      {{ asc: ' ↑', desc: ' ↓' }[h.column.getIsSorted() as string] ?? null}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {visibleRows.map((row, i) => (
                <tr
                  key={row.id}
                  className="clickable"
                  style={i === selIdx ? { background: 'var(--accent-wash)', boxShadow: 'inset 2px 0 0 var(--accent)' } : undefined}
                  onMouseEnter={() => setSelIdx(i)}
                  onClick={() => nav(`/cases/${row.original.sha256}/orch`)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
