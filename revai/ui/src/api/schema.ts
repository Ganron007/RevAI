import { z } from 'zod'

/** Accept JSON null as well as undefined for optional scalars. */
const optStr = z.string().nullish()
const optBool = z.boolean().nullish()
const optNum = z.number().nullish()

export const SampleSchema = z
  .object({
    sha256: z.string(),
    sha_short: optStr,
    display_name: optStr,
    project_name: optStr,
    group: optStr,
    date_bucket: optStr,
    file_type: optStr,
    os: optStr,
    arch: optStr,
    bits: optNum,
    staged_at: optStr,
    sample_path: optStr,
    pipeline_mode: optStr,
    verdict: optStr,
    family_guess: optStr,
    score: optNum,
    error: optStr,
  })
  .passthrough()

export type Sample = z.infer<typeof SampleSchema>

export const EvidenceFileSchema = z
  .object({
    path: z.string(),
    size: z.number(),
    stage: z.string(),
    ext: z.string(),
    mtime: optNum,
    curated: z.boolean().optional(),
    kind: optStr,
  })
  .passthrough()

export type EvidenceFile = z.infer<typeof EvidenceFileSchema>

export const OrchToolSchema = z
  .object({
    tool: optStr,
    stage: optStr,
    status: optStr,
    rc: optNum,
    duration_s: optNum,
    started_at: optStr,
    finished_at: optStr,
    line: optStr,
    detail: optStr,
  })
  .passthrough()

export const OrchLiveSchema = z
  .object({
    sha: z.string(),
    status: z.string(),
    running: z.boolean(),
    current: optStr,
    current_tool: optStr,
    current_stage: optStr,
    tools: z.array(OrchToolSchema).nullish().transform((v) => v ?? []),
    log_tail: z.array(z.string()).nullish().transform((v) => v ?? []),
    task_log_tail: z.array(z.string()).nullish().transform((v) => v ?? []),
    task_id: optStr,
    task_status: optStr,
    truly_green: optBool,
    quality_green: optBool,
    all_green: optBool,
    quality_issues: z
      .array(z.union([z.string(), z.record(z.string(), z.unknown())]))
      .nullish()
      .transform((v) =>
        (v ?? []).map((x) => (typeof x === 'string' ? x : JSON.stringify(x))),
      ),
    quality_checks: z
      .record(
        z.string(),
        z
          .object({
            ok: optBool,
            source: optStr,
            chars: optNum,
            label: optStr,
          })
          .passthrough(),
      )
      .nullish()
      .transform((v) => v ?? {}),
    planner_model: optStr,
    judgment_model: optStr,
    deep: z
      .object({
        checklist_ok: optBool,
        sql_deep_ok: optBool,
        successful_tool_calls: z.unknown().optional(),
        verdict: optStr,
        engine: optStr,
      })
      .passthrough()
      .nullish()
      .transform((v) => v ?? {}),
    stages_run: z.array(z.string()).nullish(),
    elapsed_s: optNum,
    artifacts: z.record(z.string(), z.boolean()).nullish(),
  })
  .passthrough()

export type OrchLive = z.infer<typeof OrchLiveSchema>

export const StageResultSchema = z
  .object({
    ok: z.boolean(),
    sha256: optStr,
    family: optStr,
    error: optStr,
    sample_path: optStr,
    project_name: optStr,
  })
  .passthrough()

export const BrowseSchema = z.object({
  dirs: z.array(
    z.object({
      path: z.string(),
      n_files: optNum,
      files: z
        .array(
          z
            .object({
              name: z.string(),
              is_dir: z.boolean().optional(),
              size: optNum,
            })
            .passthrough(),
        )
        .nullish()
        .transform((v) => v ?? []),
    }),
  ),
  upload: z
    .object({
      dropbox: optStr,
      note: optStr,
      commands: z.record(z.string(), z.string()).optional(),
    })
    .passthrough()
    .nullish(),
})

export type BrowsePayload = z.infer<typeof BrowseSchema>

export const HitlPendingSchema = z
  .object({
    sha: optStr,
    pending_count: z.number().nullish().transform((v) => v ?? 0),
    pending: z
      .array(
        z
          .object({
            address: optNum,
            new_name: optStr,
            comment: optStr,
            confidence: optNum,
            hitl_status: optStr,
          })
          .passthrough(),
      )
      .nullish()
      .transform((v) => v ?? []),
    overall_confidence: optNum,
    error: optStr,
  })
  .passthrough()

export type HitlPending = z.infer<typeof HitlPendingSchema>

export const LlmSettingsSchema = z
  .object({
    llm_model: optStr,
    llm_api_url: optStr,
    llm_api_key: optStr,
    llm_api_key_set: z.boolean().optional(),
    llm_reasoning: optStr,
    use_rag: optBool,
    product_mode: optStr,
    run_config: z
      .object({
        profile: optStr,
        stage_retries: optNum,
        tool_retries: optNum,
        timeout_scale: optNum,
        recursion_limit: optNum,
        deep_max_steps: optNum,
        retry_transient_only: optBool,
        budget_warnings: optBool,
        redundant_nudge: optBool,
        hallucination_check: optBool,
        failure_taxonomy: optBool,
      })
      .optional(),
  })
  .passthrough()

export type LlmSettings = z.infer<typeof LlmSettingsSchema>

export type RunConfig = NonNullable<LlmSettings['run_config']>

export const PipelineStageSchema = z
  .object({
    id: z.string(),
    label: z.string(),
    script: optStr,
    num: optNum,
    title: optStr,
    desc: optStr,
    long_desc: optStr,
    artifacts: z.array(z.string()).nullish().transform((v) => v ?? []),
    deps: z.array(z.string()).nullish().transform((v) => v ?? []),
    dir: optStr,
  })
  .passthrough()

export const PipelineMapSchema = z
  .object({
    stages: z.array(PipelineStageSchema).nullish().transform((v) => v ?? []),
    gates: z.record(z.string(), z.string()).nullish().transform((v) => v ?? {}),
    product_mode: optStr,
    planner_model: optStr,
    dropbox: optStr,
  })
  .passthrough()

export type PipelineMap = z.infer<typeof PipelineMapSchema>
export type PipelineStage = z.infer<typeof PipelineStageSchema>

export const STAGE_ORDER = [
  'intake',
  'quick_scan',
  'deep_dive',
  'yara_gen',
  'publish',
  'correlate',
  'audit',
] as const

export const STAGE_LABELS: Record<string, string> = {
  intake: 'Intake',
  quick_scan: 'Quick Scan',
  deep_dive: 'Deep Dive',
  yara_gen: 'YARA',
  publish: 'Publish',
  correlate: 'Section',
  audit: 'Audit',
  check_quality: 'Quality',
}
