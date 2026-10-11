import { z } from 'zod'

const optStr = z.string().nullish().transform((v) => v ?? '')

/** One recorded analyst note. */
export const SteeringRecordSchema = z.object({
  note: optStr,
  level: optStr,
  at: optStr,
  sha: optStr,
})

export type SteeringRecord = z.infer<typeof SteeringRecordSchema>

/** GET /api/steer/<sha> — the recorded history plus the note now in force. */
export const SteeringHistorySchema = z.object({
  sha: optStr,
  history: z.array(SteeringRecordSchema).nullish().transform((v) => v ?? []),
  latest: optStr,
})

export type SteeringHistory = z.infer<typeof SteeringHistorySchema>
