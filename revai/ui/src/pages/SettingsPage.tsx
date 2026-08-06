import { useEffect, useState } from 'react'
import { getSettings, saveSettings } from '../api/client'
import type { LlmSettings, RunConfig } from '../api/types'
import { Button, ErrorBanner, Field, Icon, Input, Muted, NoteBanner, PageHeader, Panel, Select } from '../ds'

const PROFILES: Array<{ value: string; label: string; hint: string }> = [
  { value: 'standard', label: 'Standard', hint: '40 recursion · 16 steps · 1 retry' },
  { value: 'generous', label: 'Generous', hint: '80 recursion · 32 steps · 2 retries' },
  { value: 'unlimited', label: 'Unlimited (lab)', hint: '200 recursion · 64 steps · 5 retries' },
]

const DEFAULT_RUN_CONFIG: RunConfig = {
  profile: 'standard',
  stage_retries: 1,
  timeout_scale: 1,
  recursion_limit: 40,
  deep_max_steps: 16,
  retry_transient_only: true,
}

export default function SettingsPage() {
  const [cfg, setCfg] = useState<LlmSettings>({})
  const [rc, setRc] = useState<RunConfig>(DEFAULT_RUN_CONFIG)
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [keyDraft, setKeyDraft] = useState('')

  useEffect(() => {
    void (async () => {
      try {
        const s = await getSettings()
        setCfg(s)
        setRc({ ...DEFAULT_RUN_CONFIG, ...(s.run_config || {}) })
        setKeyDraft('') // never bind masked *** into the controlled input
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e))
      }
    })()
  }, [])

  const save = async () => {
    setSaving(true)
    setErr(null)
    setMsg(null)
    try {
      const res = await saveSettings({
        llm_model: cfg.llm_model || '',
        llm_api_url: cfg.llm_api_url || '',
        llm_api_key: keyDraft, // empty / *** skipped server-side → keep existing
        llm_reasoning: cfg.llm_reasoning || '',
        use_rag: false,
        run_config: {
          profile: rc.profile || 'standard',
          stage_retries: Number(rc.stage_retries ?? 1),
          timeout_scale: Number(rc.timeout_scale ?? 1),
          recursion_limit: Number(rc.recursion_limit ?? 40),
          deep_max_steps: Number(rc.deep_max_steps ?? 16),
          retry_transient_only: Boolean(rc.retry_transient_only),
        },
      })
      setCfg(res.config)
      setKeyDraft('')
      setMsg('Saved · LLM + run configuration')
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="app-main" style={{ overflowY: 'auto' }}>
      <div style={{ maxWidth: 560, margin: '0 auto' }}>
        <PageHeader title="Settings" subtitle="LLM-only · static RE · LangGraph orch" />
        {err && <ErrorBanner>{err}</ErrorBanner>}
        {msg && <NoteBanner>{msg}</NoteBanner>}

        <Panel title="LLM backend" style={{ marginTop: 'var(--sp-4)' }}>
          <div style={{ display: 'grid', gap: 'var(--sp-3)' }}>
            <Field label="Model">
              <Input
                value={cfg.llm_model || ''}
                onChange={(e) => setCfg({ ...cfg, llm_model: e.target.value })}
                placeholder="deepseek-v4-flash / deepseek-v4-pro"
              />
            </Field>
            <Field label="API URL">
              <Input
                value={cfg.llm_api_url || ''}
                onChange={(e) => setCfg({ ...cfg, llm_api_url: e.target.value })}
                placeholder="https://api.deepseek.com"
              />
            </Field>
            <Field
              label={`API key${cfg.llm_api_key_set ? ' (set)' : ''}`}
              hint="stored in chmod-600 /opt/secrets/cadre-ui.env, never in pipeline-config.json"
            >
              <Input
                type="password"
                value={keyDraft}
                onChange={(e) => setKeyDraft(e.target.value)}
                placeholder={cfg.llm_api_key_set ? '•••••••• (leave blank to keep)' : 'stored server-side'}
                autoComplete="off"
              />
            </Field>
            <Field label="Reasoning">
              <Input
                value={cfg.llm_reasoning || ''}
                onChange={(e) => setCfg({ ...cfg, llm_reasoning: e.target.value })}
                placeholder="max"
              />
            </Field>
            <Muted>
              Product mode: {cfg.product_mode || 'LLM-only · static RE · LangGraph orch'} · use_rag=false
            </Muted>
          </div>
        </Panel>

        <Panel title="Run configuration" style={{ marginTop: 'var(--sp-4)' }}>
          <Muted>
            Applied to every pipeline run started from this console (agentic retries,
            budgets, tool timeout scale). CLI runs can override via REVAI_* env vars.
          </Muted>
          <div style={{ display: 'grid', gap: 'var(--sp-3)', marginTop: 'var(--sp-3)' }}>
            <Field label="Budget profile">
              <Select
                value={rc.profile || 'standard'}
                onChange={(e) => setRc({ ...rc, profile: e.target.value })}
              >
                {PROFILES.map((p) => (
                  <option key={p.value} value={p.value}>
                    {p.label} — {p.hint}
                  </option>
                ))}
              </Select>
            </Field>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-3)' }}>
              <Field label="Stage retries" hint="transient failures only (0 = none)">
                <Input
                  type="number"
                  min={0}
                  max={10}
                  value={rc.stage_retries ?? 1}
                  onChange={(e) => setRc({ ...rc, stage_retries: Number(e.target.value) })}
                />
              </Field>
              <Field label="Tool timeout scale" hint="1.0 = manifest timeouts">
                <Input
                  type="number"
                  step={0.5}
                  min={0.5}
                  max={10}
                  value={rc.timeout_scale ?? 1}
                  onChange={(e) => setRc({ ...rc, timeout_scale: Number(e.target.value) })}
                />
              </Field>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-3)' }}>
              <Field label="Orchestrator recursion" hint="planner tool-call budget">
                <Input
                  type="number"
                  min={10}
                  max={500}
                  value={rc.recursion_limit ?? 40}
                  onChange={(e) => setRc({ ...rc, recursion_limit: Number(e.target.value) })}
                />
              </Field>
              <Field label="Deep-dive max steps" hint="agent loop steps">
                <Input
                  type="number"
                  min={4}
                  max={128}
                  value={rc.deep_max_steps ?? 16}
                  onChange={(e) => setRc({ ...rc, deep_max_steps: Number(e.target.value) })}
                />
              </Field>
            </div>
            <Field label="Retry only transient failures">
              <Select
                value={rc.retry_transient_only === false ? '0' : '1'}
                onChange={(e) => setRc({ ...rc, retry_transient_only: e.target.value === '1' })}
              >
                <option value="1">Yes — timeout / MCP / connection only (recommended)</option>
                <option value="0">No — retry any failure</option>
              </Select>
            </Field>
          </div>
        </Panel>
        <div style={{ marginTop: 'var(--sp-3)' }}>
          <Button tone="primary" disabled={saving} onClick={() => void save()} icon={<Icon.check size={13} />}>
            {saving ? 'Saving…' : 'Save'}
          </Button>
        </div>
      </div>
    </div>
  )
}
