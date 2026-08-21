import {
  BrowseSchema,
  EvidenceFileSchema,
  HitlPendingSchema,
  LlmSettingsSchema,
  OrchLiveSchema,
  PipelineMapSchema,
  SampleSchema,
  StageResultSchema,
  type BrowsePayload,
  type EvidenceFile,
  type HitlPending,
  type LlmSettings,
  type OrchLive,
  type PipelineMap,
  type Sample,
} from './schema'

async function raw(path: string, init?: RequestInit): Promise<unknown> {
  const res = await fetch(path, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.error || body.message || JSON.stringify(body)
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${detail}`)
  }
  if (res.status === 204) return undefined
  return res.json()
}

export async function getSamples(): Promise<Sample[]> {
  const data = await raw('/api/samples')
  return SampleSchema.array().parse(data)
}

export async function getModes(sha: string): Promise<string[]> {
  const data = (await raw(`/api/modes/${sha}`)) as { modes?: string[] }
  return data.modes ?? []
}

export async function getStatus(sha: string, mode?: string | null) {
  const q = mode ? `?mode=${encodeURIComponent(mode)}` : ''
  return raw(`/api/status/${sha}${q}`) as Promise<Record<string, unknown>>
}

export async function getEvidence(sha: string, mode?: string | null): Promise<EvidenceFile[]> {
  const q = mode ? `?mode=${encodeURIComponent(mode)}` : ''
  const data = await raw(`/api/evidence/${sha}${q}`)
  return EvidenceFileSchema.array().parse(data)
}

export async function getReports(sha: string, internals = false, mode?: string | null): Promise<EvidenceFile[]> {
  const params = new URLSearchParams()
  if (internals) params.set('internals', '1')
  if (mode) params.set('mode', mode)
  const q = params.toString() ? `?${params}` : ''
  const data = await raw(`/api/artifacts/${sha}/reports${q}`)
  const parsed = data as { files?: unknown }
  return EvidenceFileSchema.array().parse(parsed.files ?? data)
}

export async function getFileText(sha: string, path: string, mode?: string | null) {
  const q = new URLSearchParams({ path })
  if (mode) q.set('mode', mode)
  const res = await fetch(`/api/file/${sha}?${q}`)
  if (!res.ok) throw new Error(`file ${res.status}`)
  return res.text()
}

export async function getRenderHtml(sha: string, path: string, type = '', mode?: string | null) {
  const q = new URLSearchParams({ path })
  if (type) q.set('type', type)
  if (mode) q.set('mode', mode)
  const res = await fetch(`/api/render/${sha}?${q}`)
  if (!res.ok) throw new Error(`render ${res.status}`)
  const ct = res.headers.get('content-type') || ''
  if (ct.includes('application/json')) {
    const j = await res.json()
    return typeof j.html === 'string' ? j.html : JSON.stringify(j, null, 2)
  }
  return res.text()
}

export async function runStage(sha: string, stage: string) {
  return raw(`/api/run/${sha}/${stage}`, { method: 'POST' }) as Promise<{ task_id: string }>
}

export async function getTask(taskId: string) {
  return raw(`/api/task/${taskId}`) as Promise<{
    task_id: string
    status: string
    returncode?: number
    log_tail?: string[]
  }>
}

export async function orchStart(sha: string) {
  const data = await raw('/api/orch/start', {
    method: 'POST',
    body: JSON.stringify({ sha }),
  })
  return data as { ok: boolean; task_id?: string; error?: string }
}

export async function orchStop(sha: string) {
  return raw(`/api/orch/${sha}/stop`, { method: 'POST' }) as Promise<{ ok: boolean }>
}

export async function orchLive(sha: string, mode?: string | null): Promise<OrchLive> {
  const q = mode ? `?mode=${encodeURIComponent(mode)}` : ''
  const data = await raw(`/api/orch/${sha}/live${q}`)
  const parsed = OrchLiveSchema.safeParse(data)
  if (parsed.success) return parsed.data
  console.warn('orchLive schema warning', parsed.error.message)
  return data as OrchLive
}

export async function orchTrace(sha: string, mode?: string | null) {
  const q = mode ? `?mode=${encodeURIComponent(mode)}` : ''
  return raw(`/api/orch/${sha}/trace${q}`) as Promise<Record<string, unknown>>
}

export async function orchActive() {
  return raw('/api/orch/active') as Promise<{ active: Array<{ sha: string; pid: number }> }>
}

export async function getQuality(sha: string, mode?: string | null) {
  const q = mode ? `?mode=${encodeURIComponent(mode)}` : ''
  return raw(`/api/quality/${sha}${q}`) as Promise<Record<string, unknown>>
}

export async function getBrowse(): Promise<BrowsePayload> {
  const data = await raw('/api/browse')
  return BrowseSchema.parse(data)
}

export async function getPipelineMap(): Promise<PipelineMap> {
  const data = await raw('/api/pipeline-map')
  return PipelineMapSchema.parse(data)
}

export async function getIntakeProgress(sha: string) {
  return raw(`/api/intake-progress/${sha}`) as Promise<{
    stage?: string
    pct?: number
    msg?: string
    returncode?: number
  }>
}

export async function stageSample(src_path: string, family: string) {
  const data = await raw('/api/stage', {
    method: 'POST',
    body: JSON.stringify({ src_path, family }),
  })
  return StageResultSchema.parse(data)
}

export async function getHitlPending(sha: string, mode?: string | null): Promise<HitlPending> {
  try {
    const q = mode ? `?mode=${encodeURIComponent(mode)}` : ''
    const data = await raw(`/api/hitl/${sha}/pending${q}`)
    return HitlPendingSchema.parse(data)
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    if (msg.includes('404')) {
      return { pending_count: 0, pending: [], error: 'no deep-dive yet' }
    }
    throw e
  }
}

export async function hitlApprove(sha: string, address?: number, mode?: string | null) {
  const q = mode ? `?mode=${encodeURIComponent(mode)}` : ''
  return raw(`/api/hitl/${sha}/approve${q}`, {
    method: 'POST',
    body: JSON.stringify(address != null ? { address } : {}),
  })
}

export async function hitlReject(sha: string, address?: number, mode?: string | null) {
  const q = mode ? `?mode=${encodeURIComponent(mode)}` : ''
  return raw(`/api/hitl/${sha}/reject${q}`, {
    method: 'POST',
    body: JSON.stringify(address != null ? { address } : {}),
  })
}

export async function getSettings(): Promise<LlmSettings> {
  const data = await raw('/api/settings')
  return LlmSettingsSchema.parse(data)
}

export async function saveSettings(body: Partial<LlmSettings>) {
  const data = await raw('/api/settings', {
    method: 'POST',
    body: JSON.stringify(body),
  })
  return data as { ok: boolean; config: LlmSettings }
}
