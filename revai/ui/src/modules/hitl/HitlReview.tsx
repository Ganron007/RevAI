import { useCallback, useEffect, useState } from 'react'
import { getHitlPending, hitlApprove, hitlReject } from '../../api/client'
import type { HitlPending } from '../../api/types'
import { Badge, Button, ConfBar, EmptyState, ErrorBanner, Icon, NoteBanner, Panel, Toolbar } from '../../ds'
import { useCase } from '../../pages/caseContext'

const CRITICAL_TAGS = /\b(critical|destructive|exfil|ransom|wipe|inject)\b/i

export default function HitlReview() {
  const { sha, refreshHitl, mode: runMode } = useCase()
  const [data, setData] = useState<HitlPending | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setErr(null)
    try {
      setData(await getHitlPending(sha, runMode))
      await refreshHitl?.()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    }
  }, [sha, runMode, refreshHitl])

  useEffect(() => {
    void load()
  }, [load])

  const act = async (kind: 'approve' | 'reject', address?: number) => {
    setMsg(null)
    setBusy(true)
    try {
      if (kind === 'approve') await hitlApprove(sha, address, runMode)
      else await hitlReject(sha, address, runMode)
      setMsg(`${kind} ok`)
      await load()
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const pending = data?.pending || []
  const critical = pending.filter((a) => CRITICAL_TAGS.test(`${a.new_name || ''} ${a.comment || ''}`))
  const normal = pending.filter((a) => !critical.includes(a))

  return (
    <div>
      {err && <ErrorBanner>{err}</ErrorBanner>}
      {msg && <NoteBanner>{msg}</NoteBanner>}
      <Toolbar>
        <Button size="sm" tone="ghost" icon={<Icon.refresh size={12} />} onClick={() => void load()}>
          Refresh
        </Button>
        <Button tone="primary" disabled={busy || !pending.length} onClick={() => void act('approve')}>
          Approve all pending
        </Button>
        <span className="muted" style={{ fontSize: 'var(--tx-sm)' }}>
          {data?.pending_count ?? 0} pending
        </span>
      </Toolbar>

      {!pending.length ? (
        <Panel>
          <EmptyState title={data?.error || 'Nothing pending'} detail="Complete a deep dive to populate the HITL queue" />
        </Panel>
      ) : (
        <div className="table-wrap">
          <table className="dt">
            <thead>
              <tr>
                <th>Address</th>
                <th>Proposed name</th>
                <th>Confidence</th>
                <th>Comment</th>
                <th style={{ textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {critical.map((a, i) => (
                <HitlRow key={`c-${a.address}-${i}`} a={a} critical busy={busy} onAct={act} />
              ))}
              {normal.map((a, i) => (
                <HitlRow key={`n-${a.address}-${i}`} a={a} busy={busy} onAct={act} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function HitlRow({
  a,
  critical,
  busy,
  onAct,
}: {
  a: NonNullable<HitlPending['pending']>[number]
  critical?: boolean
  busy: boolean
  onAct: (kind: 'approve' | 'reject', address?: number) => void
}) {
  return (
    <tr style={critical ? { background: 'var(--danger-wash)', boxShadow: 'inset 2px 0 0 var(--danger)' } : undefined}>
      <td className="mono">{a.address != null ? `0x${Number(a.address).toString(16)}` : '—'}</td>
      <td>
        <span style={{ fontWeight: 600 }}>{a.new_name || '—'}</span>
        {critical && (
          <Badge tone="danger">
            <Icon.alert size={11} /> critical
          </Badge>
        )}
      </td>
      <td>
        <ConfBar value={a.confidence} />
      </td>
      <td className="tx1 ellipsis" style={{ maxWidth: 320 }}>
        {(a.comment || '').slice(0, 100)}
      </td>
      <td style={{ textAlign: 'right' }}>
        <Button size="sm" disabled={busy} icon={<Icon.check size={12} />} onClick={() => void onAct('approve', a.address ?? undefined)}>
          Approve
        </Button>{' '}
        <Button size="sm" tone="danger" disabled={busy} icon={<Icon.close size={12} />} onClick={() => void onAct('reject', a.address ?? undefined)}>
          Reject
        </Button>
      </td>
    </tr>
  )
}
