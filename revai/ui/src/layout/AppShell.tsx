import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import CommandPalette from '../components/CommandPalette'
import { Icon } from '../ds'
import { LogoMark } from '../ds/Logo'

export default function AppShell() {
  const [online, setOnline] = useState(true)
  const [paletteOpen, setPaletteOpen] = useState(false)

  useEffect(() => {
    let cancelled = false
    const ping = async () => {
      try {
        const r = await fetch('/api/samples', { method: 'HEAD' }).catch(() => fetch('/api/samples'))
        if (!cancelled) setOnline(r.ok || r.status === 405 || r.status === 200)
      } catch {
        if (!cancelled) setOnline(false)
      }
    }
    void ping()
    const id = window.setInterval(ping, 30000)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="app-shell">
      <header className="topbar">
        <NavLink to="/" className="topbar-brand">
          <LogoMark size={22} />
          CADRE<span style={{ color: 'var(--tx-2)', fontWeight: 400 }}>//</span>RevAI
          <span className="sub">Console</span>
        </NavLink>
        <nav className="topbar-nav">
          <NavLink to="/" end>
            Home
          </NavLink>
          <NavLink to="/cases">Cases</NavLink>
          <NavLink to="/stage">Stage</NavLink>
          <NavLink to="/help">Help</NavLink>
          <NavLink to="/settings">Settings</NavLink>
        </nav>
        <div className="topbar-right">
          <button className="palette-trigger" onClick={() => setPaletteOpen(true)}>
            <Icon.search size={13} />
            Search or command…
            <kbd>Ctrl K</kbd>
          </button>
          <span className={`api-health ${online ? 'up' : 'down'}`} data-tip={online ? 'API reachable' : 'API unreachable'}>
            <span className="dot" />
            {online ? 'API' : 'DOWN'}
          </span>
        </div>
      </header>
      <div className="app-body">
        <Outlet />
      </div>
      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}
    </div>
  )
}
