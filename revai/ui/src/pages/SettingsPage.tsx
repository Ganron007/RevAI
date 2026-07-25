import { useEffect, useState } from 'react'
import { getSettings, saveSettings } from '../api/client'
import type { LlmSettings } from '../api/types'
import { Button, ErrorBanner, Field, Icon, Input, Muted, NoteBanner, PageHeader, Panel } from '../ds'

export default function SettingsPage() {
  const [cfg, setCfg] = useState<LlmSettings>({})
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [keyDraft, setKeyDraft] = useState('')

  useEffect(() => {
    void (async () => {
      try {
        const s = await getSettings()
        setCfg(s)
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
      })
      setCfg(res.config)
      setKeyDraft('')
      setMsg('Saved · LLM-only · RAG forced off')
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
            <div>
              <Button tone="primary" disabled={saving} onClick={() => void save()} icon={<Icon.check size={13} />}>
                {saving ? 'Saving…' : 'Save'}
              </Button>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  )
}
