import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getSamples } from '../api/client'
import type { Sample } from '../api/types'
import { Icon } from '../ds'

type Item = {
  id: string
  label: string
  hint?: string
  icon?: React.ReactNode
  run: () => void
}

export default function CommandPalette({ onClose }: { onClose: () => void }) {
  const nav = useNavigate()
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(0)
  const [samples, setSamples] = useState<Sample[]>([])
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    inputRef.current?.focus()
    void getSamples()
      .then((s) => setSamples(s.slice(0, 50)))
      .catch(() => setSamples([]))
  }, [])

  const items = useMemo<Item[]>(() => {
    const go = (to: string) => () => {
      nav(to)
      onClose()
    }
    const base: Item[] = [
      { id: 'home', label: 'Go to Home', hint: 'g h', icon: <Icon.home />, run: go('/') },
      { id: 'cases', label: 'Go to Cases', hint: 'g c', icon: <Icon.cases />, run: go('/cases') },
      { id: 'stage', label: 'Stage a sample', hint: 'g s', icon: <Icon.stage />, run: go('/stage') },
      { id: 'help', label: 'Help & pipeline guide', hint: 'g ?', icon: <Icon.reports />, run: go('/help') },
      { id: 'settings', label: 'Settings', hint: 'g ,', icon: <Icon.settings />, run: go('/settings') },
    ]
    const query = q.trim().toLowerCase()
    const matched = query
      ? samples
          .filter((s) => {
            const name = (s.display_name || '').toLowerCase()
            const fam = (s.family_guess || s.project_name || '').toLowerCase()
            return name.includes(query) || fam.includes(query) || s.sha256.startsWith(query)
          })
          .slice(0, 8)
          .map<Item>((s) => ({
            id: `case-${s.sha256}`,
            label: s.display_name || `${s.sha256.slice(0, 12)}…`,
            hint: `${(s.family_guess || s.project_name || 'unknown')} · ${s.sha256.slice(0, 12)}`,
            icon: <Icon.cases />,
            run: go(`/cases/${s.sha256}/orch`),
          }))
      : []
    const all = [...matched, ...base]
    return all.filter((it) => !query || it.id.startsWith('case-') || it.label.toLowerCase().includes(query))
  }, [q, samples, nav, onClose])

  useEffect(() => {
    setSel(0)
  }, [q])

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      onClose()
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSel((v) => Math.min(v + 1, items.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSel((v) => Math.max(v - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      items[sel]?.run()
    }
  }

  return (
    <div className="palette-overlay" onClick={onClose}>
      <div className="palette" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={onKey}
          placeholder="Jump to case, or command…"
        />
        <div className="palette-list">
          {items.length === 0 && <div className="palette-item">No matches</div>}
          {items.map((it, i) => (
            <div
              key={it.id}
              className={`palette-item${i === sel ? ' sel' : ''}`}
              onMouseEnter={() => setSel(i)}
              onClick={it.run}
            >
              {it.icon}
              <span>{it.label}</span>
              {it.hint && <span className="hint">{it.hint}</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
