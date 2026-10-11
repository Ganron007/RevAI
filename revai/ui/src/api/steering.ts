import { raw } from './client'
import {
  SteeringHistorySchema,
  type SteeringHistory,
} from './steering-schema'

export async function getSteering(sha: string): Promise<SteeringHistory> {
  const data = await raw(`/api/steer/${sha}`)
  return SteeringHistorySchema.parse(data)
}

/**
 * Record a post-hoc analyst note (L3).
 *
 * The note is CONTEXT for the next run: it may redirect where the analysis
 * looks, and it can never set a verdict, skip a stage or bypass a gate. The
 * UI says so, because a steering surface that looks like a command surface
 * will be used as one.
 */
export async function postSteering(
  sha: string,
  note: string,
): Promise<SteeringHistory> {
  const data = await raw(`/api/steer/${sha}`, {
    method: 'POST',
    body: JSON.stringify({ note }),
  })
  return SteeringHistorySchema.parse(data)
}
