import { useCallback, useEffect, useState } from 'react'
import { getSteering, postSteering } from '../../api/steering'
import type { SteeringHistory } from '../../api/steering-schema'
import {
  Badge,
  Button,
  EmptyState,
  ErrorBanner,
  NoteBanner,
  Panel,
  Toolbar,
} from '../../ds'
import { useCase } from '../../pages/caseContext'

const MAX = 2000

/**
 * L3 post-hoc steering: record analyst direction on a case, for the next run.
 *
 * The wording of the safety banner is not decoration. A steering surface that
 * looks like a command surface gets used as one, so the limits are stated where
 * the analyst types: the note is context, it may be wrong, it never becomes a
 * finding, and it cannot set a verdict.
 */
export default function SteeringPanel() {
  const { sha } = useCase()
  const [data, setData] = useState<SteeringHistory | null>(null)
  const [draft, setDraft] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setErr(null)
    try {
      setData(await getSteering(sha))
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    }
  }, [sha])

  useEffect(() => {
    void load()
  }, [load])

  const submit = async () => {
    const note = draft.trim()
    if (!note) return
    setMsg(null)
    setErr(null)
    setBusy(true)
    try {
      const next = await postSteering(sha, note)
      setData(next)
      setDraft('')
      setMsg('Recorded. It applies to the next run of this sample.')
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  const history = data?.history ?? []
  const latest = data?.latest ?? ''

  return (
    <Panel title="Analyst steering">
      <p style={{ opacity: 0.75, marginTop: 0 }}>
        Direction recorded for the next run of this sample.
      </p>
      <NoteBanner>
        A steering note is <strong>context, not instructions</strong>. It may
        redirect where the analysis looks; it can never set a verdict, skip a
        stage, or bypass a gate. It may be wrong about any specific fact — tool
        evidence outranks it — and it is never reported as a finding.
      </NoteBanner>

      {latest ? (
        <NoteBanner>
          <strong>In force for the next run:</strong> {latest}
        </NoteBanner>
      ) : (
        <EmptyState
          title="No steering note recorded"
          detail="The next run of this sample will be unsteered."
        />
      )}

      <Toolbar>
        <textarea
          value={draft}
          maxLength={MAX}
          rows={4}
          placeholder="e.g. focus on the persistence mechanism — the domain nodes keep skipping it"
          onChange={(e) => setDraft(e.target.value)}
          style={{ width: '100%' }}
        />
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ opacity: 0.7 }}>
            {draft.length}/{MAX}
          </span>
          <Button onClick={submit} disabled={busy || !draft.trim()}>
            {busy ? 'Recording…' : 'Record note'}
          </Button>
        </div>
      </Toolbar>

      {msg ? <NoteBanner>{msg}</NoteBanner> : null}
      {err ? <ErrorBanner>{err}</ErrorBanner> : null}

      {history.length > 0 ? (
        <>
          <h4>Recorded history</h4>
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Level</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {history
                .slice()
                .reverse()
                .map((r, i) => (
                  <tr key={`${r.at}-${i}`}>
                    <td>
                      <Badge>{r.at || '—'}</Badge>
                    </td>
                    <td>{r.level || '—'}</td>
                    <td>{r.note}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </>
      ) : null}
    </Panel>
  )
}
