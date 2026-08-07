import { useEffect, useState } from 'react'
import { getPipelineMap } from '../api/client'
import type { PipelineMap } from '../api/types'
import { Badge, Icon, PageHeader, SourceBadge } from '../ds'

const SCP_CMD = `scp -i "/path/to/your-ssh-key" \\
  "/path/to/sample.exe" \\
  remnux@<remnux-ip>:/opt/samples/incoming/user-drop/`

const SHORTCUTS: Array<[string, string]> = [
  ['Ctrl + K', 'Open command palette (jump to any case or page)'],
  ['j / k', 'Move selection down / up in the cases table'],
  ['Enter', 'Open the selected case'],
  ['r', 'Soft-refresh the cases table'],
]

export default function HelpPage() {
  const [pmap, setPmap] = useState<PipelineMap | null>(null)

  useEffect(() => {
    let cancelled = false
    void getPipelineMap()
      .then((p) => {
        if (!cancelled) setPmap(p)
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div className="app-main" style={{ overflowY: 'auto' }}>
      <div style={{ maxWidth: 860, margin: '0 auto' }}>
        <PageHeader title="Help & pipeline guide" subtitle="how the console and the analysis pipeline work" />

        <Section id="start" title="Getting started">
          <p>
            This console drives a <strong>seven-stage malware-analysis pipeline</strong> (plus one{' '}
            <em>optional</em> function-recovery stage) on the REMnux
            lab host. You stage a binary, the orchestrator runs every stage, and each run is gated on
            evidence quality. There are three main areas:
          </p>
          <ul className="help-list">
            <li>
              <strong>Stage</strong> — bring a new sample in (kept separate so you never touch existing
              analyses by accident).
            </li>
            <li>
              <strong>Cases</strong> — every staged sample; open one to review its run, reports,
              evidence and audit trail.
            </li>
            <li>
              <strong>Settings</strong> — the LLM backend used for judgment and reporting.
            </li>
          </ul>
        </Section>

        <Section id="stage" title="Staging a sample">
          <p>
            For safety there is <strong>no browser upload</strong>. Copy the binary to the dropbox over
            SCP, then stage it from the UI (the file appears under <em>Browse</em>, or paste the path).
          </p>
          <div className="help-code">
            <div className="help-code-head">
              <span className="mono">upload to dropbox</span>
              <span className="muted" style={{ fontSize: 'var(--tx-xs)' }}>{pmap?.dropbox || '/opt/samples/incoming/user-drop'}</span>
            </div>
            <pre className="console" style={{ border: 0, borderRadius: 0, margin: 0, maxHeight: 'none' }}>{SCP_CMD}</pre>
          </div>
          <p className="muted" style={{ fontSize: 'var(--tx-sm)' }}>
            Only paths under <span className="mono">/opt/samples/incoming</span> and{' '}
            <span className="mono">/opt/samples/mta-routing</span> are accepted — anything else is
            rejected by the staging gate.
          </p>
        </Section>

        <Section id="pipeline" title="The stages">
          <p>
            Each stage writes evidence under the case log. The orchestrator runs them in order and a
            run is only trusted if the gates below pass. <strong>Function Recovery</strong> is
            optional — enable it in <em>Settings → Run configuration</em> (agentic recovery); it
            self-skips with rc=0 when disabled, so it never blocks a run.
          </p>
          <div style={{ display: 'grid', gap: 'var(--sp-3)' }}>
            {(pmap?.stages || []).map((st, i) => (
              <div key={st.id} className="panel" style={{ padding: 'var(--sp-3) var(--sp-4)' }}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--sp-2)' }}>
                  <span className="mono" style={{ color: 'var(--accent-hi)', fontSize: 'var(--tx-xs)' }}>
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  <strong style={{ fontSize: 'var(--tx-md)' }}>{st.label}</strong>
                  <span className="mono muted" style={{ fontSize: 'var(--tx-xs)', marginLeft: 'auto' }}>{st.script}</span>
                </div>
                <p style={{ margin: '6px 0 0', color: 'var(--tx-1)', fontSize: 'var(--tx-sm)', lineHeight: 1.55 }}>
                  {st.long_desc || st.desc}
                </p>
                {st.artifacts.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                    {st.artifacts.map((a) => (
                      <span key={a} className="mono" style={{ fontSize: '0.68rem', color: 'var(--tx-2)', background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 3, padding: '1px 6px' }}>
                        {a}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>

        <Section id="gates" title="Quality gates & verdicts">
          <p>
            A green stage is not the same as a correct report. The console surfaces the gates below and the{' '}
            <em>source</em> of every report, so a run that silently fell back to a stub can never look fine.
            The <strong>depth gate</strong> is part of the audit: the deep-dive summary must address
            every capability domain (persistence, C2/network, evasion, exfiltration, defense impairment,
            credential access, encryption, entry point, imports, strings) as evidence or an explicit
            "not observed" — an unmentioned domain fails the run.
          </p>
          <div style={{ display: 'grid', gap: 'var(--sp-2)' }}>
            {Object.entries(pmap?.gates || {}).map(([k, v]) => (
              <div key={k} className="panel" style={{ padding: 'var(--sp-2) var(--sp-3)', display: 'flex', gap: 'var(--sp-3)', alignItems: 'baseline' }}>
                <span className="mono" style={{ color: k === 'truly_green' ? 'var(--ok)' : 'var(--accent-hi)', fontWeight: 600, minWidth: 110 }}>{k}</span>
                <span style={{ color: 'var(--tx-1)', fontSize: 'var(--tx-sm)' }}>{v}</span>
              </div>
            ))}
          </div>
          <p style={{ marginTop: 'var(--sp-3)' }}>
            Report sources: <SourceBadge source="llm_judge" /> means the LLM wrote it from evidence;{' '}
            <SourceBadge source="deterministic_fallback" /> means the pipeline filled in a stub and the
            run is <strong>not</strong> trustworthy. Verdicts of <Badge tone="unknown">unknown</Badge> are
            shown neutral — never green.
          </p>
        </Section>

        <Section id="reading" title="Reading a run">
          <ul className="help-list">
            <li><strong>Orchestrator</strong> — the stage timeline, every tool call the agent made, the live log, and the quality gate bar.</li>
            <li><strong>Reports</strong> — the rendered MASTER / TECHNICAL reports with a section outline.</li>
            <li><strong>Evidence</strong> — the raw per-stage artifacts (tool output, prompts, SQL evidence).</li>
            <li><strong>HITL Review</strong> — proposed function renames that need an analyst decision before they are written back.</li>
            <li><strong>Manual Stages</strong> — run any single stage by hand (the audit stage re-runs <span className="mono">audit_pipeline.py</span> to re-check <span className="mono">all_green</span>).</li>
          </ul>
        </Section>

        <Section id="shortcuts" title="Keyboard shortcuts">
          <div className="table-wrap">
            <table className="dt">
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {SHORTCUTS.map(([k, v]) => (
                  <tr key={k}>
                    <td className="mono">{k}</td>
                    <td>{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>

        <Section id="honesty" title="Honest claims">
          <p className="muted" style={{ fontSize: 'var(--tx-sm)', lineHeight: 1.6 }}>
            Automated greens are lab evidence, not a guarantee that every report is analyst-correct.
            Filename-based enrichment and dual-use “legitimate remote-admin” narratives have poisoned
            verdicts before — the quality gates exist because of that. RevAI runs as a self-hosted,
            single-user analysis instance and is not a finished autonomous RE product.
          </p>
        </Section>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 'var(--sp-5)', color: 'var(--tx-2)', fontSize: 'var(--tx-xs)' }}>
          <Icon.check size={13} /> Still stuck? Open a case and read its Evidence tab — every stage shows exactly what it ran.
        </div>
      </div>
    </div>
  )
}

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} style={{ marginBottom: 'var(--sp-6)' }}>
      <h2 style={{ fontSize: 'var(--tx-lg)', fontWeight: 600, color: 'var(--tx-0)', marginBottom: 'var(--sp-2)', display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ width: 3, height: 18, background: 'var(--accent)', borderRadius: 2, display: 'inline-block' }} />
        {title}
      </h2>
      {children}
    </section>
  )
}
