import { createContext, useContext } from 'react'
import type { OrchLive, Sample } from '../api/types'

export type CaseCtx = {
  sha: string
  sample: Sample | null
  live: OrchLive | null
  refreshLive: () => Promise<void>
  refreshHitl?: () => Promise<void>
  mode: string | null
  modes: string[]
  setMode: (m: string | null) => void
}

export const CaseContext = createContext<CaseCtx | null>(null)

export function useCase(): CaseCtx {
  const v = useContext(CaseContext)
  if (!v) throw new Error('useCase outside CaseWorkspace')
  return v
}
