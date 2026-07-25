/**
 * RevAI Console design system — "Obsidian Ops".
 * Dense workbench primitives. One accent, semantic color = meaning.
 */
import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
} from 'react'

/* ── Icons (inline SVG, 16px grid, stroke 1.5 — Lucide-compatible paths) */
const I = ({ d, size = 14 }: { d: string; size?: number }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden
  >
    <path d={d} />
  </svg>
)

export const Icon = {
  home: (p?: { size?: number }) => <I size={p?.size} d="M3 10.5 12 3l9 7.5M5 9.5V21h5v-6h4v6h5V9.5" />,
  cases: (p?: { size?: number }) => <I size={p?.size} d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
  stage: (p?: { size?: number }) => <I size={p?.size} d="M12 3v12m0 0 4-4m-4 4-4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />,
  settings: (p?: { size?: number }) => <I size={p?.size} d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7-3a7 7 0 0 1-.1 1.2l2 1.6-2 3.4-2.4-1a7 7 0 0 1-2 1.2L14 21h-4l-.5-2.6a7 7 0 0 1-2-1.2l-2.4 1-2-3.4 2-1.6A7 7 0 0 1 5 12a7 7 0 0 1 .1-1.2l-2-1.6 2-3.4 2.4 1a7 7 0 0 1 2-1.2L10 3h4l.5 2.6a7 7 0 0 1 2 1.2l2.4-1 2 3.4-2 1.6A7 7 0 0 1 19 12Z" />,
  orch: (p?: { size?: number }) => <I size={p?.size} d="M5 3l3.6 3.6M19 3l-3.6 3.6M12 8v8m0 0-3-3m3 3 3-3M4 21h16" />,
  reports: (p?: { size?: number }) => <I size={p?.size} d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M9 13h6M9 17h6" />,
  evidence: (p?: { size?: number }) => <I size={p?.size} d="M21 21l-4.35-4.35M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z" />,
  hitl: (p?: { size?: number }) => <I size={p?.size} d="M9 11.5 11 14l4.5-5M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20Z" />,
  manual: (p?: { size?: number }) => <I size={p?.size} d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7M18.5 2.5a2.1 2.1 0 0 1 3 3L12 15l-4 1 1-4z" />,
  refresh: (p?: { size?: number }) => <I size={p?.size} d="M21 12a9 9 0 1 1-2.64-6.36M21 3v6h-6" />,
  play: (p?: { size?: number }) => <I size={p?.size} d="M6 4l14 8-14 8z" />,
  stop: (p?: { size?: number }) => <I size={p?.size} d="M6 6h12v12H6z" />,
  download: (p?: { size?: number }) => <I size={p?.size} d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />,
  close: (p?: { size?: number }) => <I size={p?.size} d="M18 6 6 18M6 6l12 12" />,
  check: (p?: { size?: number }) => <I size={p?.size} d="M20 6 9 17l-5-5" />,
  chevron: (p?: { size?: number }) => <I size={p?.size} d="M9 18l6-6-6-6" />,
  panelLeft: (p?: { size?: number }) => <I size={p?.size} d="M3 4h18v16H3zM9 4v16" />,
  copy: (p?: { size?: number }) => <I size={p?.size} d="M8 8h12v12H8zM4 16V4h12" />,
  search: (p?: { size?: number }) => <I size={p?.size} d="M21 21l-4.35-4.35M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z" />,
  pause: (p?: { size?: number }) => <I size={p?.size} d="M8 5v14M16 5v14" />,
  alert: (p?: { size?: number }) => <I size={p?.size} d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />,
}

/* ── Buttons ────────────────────────────────────────────────────────── */
type BtnTone = 'default' | 'primary' | 'danger' | 'ghost'
export function Button({
  children,
  tone = 'default',
  size,
  icon,
  className = '',
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  tone?: BtnTone
  size?: 'sm'
  icon?: ReactNode
}) {
  const cls = [
    'btn',
    tone !== 'default' ? tone : '',
    size === 'sm' ? 'sm' : '',
    icon && !children ? 'icon' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ')
  return (
    <button className={cls} {...rest}>
      {icon}
      {children}
    </button>
  )
}

/* ── Inputs ─────────────────────────────────────────────────────────── */
export function Input({ className = '', ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={`input ${className}`} {...rest} />
}

export function Select({ className = '', ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={`select ${className}`} {...rest} />
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string
  hint?: string
  children: ReactNode
}) {
  return (
    <label className="field">
      <span>
        {label}
        {hint && <span className="hint"> — {hint}</span>}
      </span>
      {children}
    </label>
  )
}

/* ── Badges ─────────────────────────────────────────────────────────── */
export type BadgeTone =
  | 'default'
  | 'ok'
  | 'warn'
  | 'danger'
  | 'info'
  | 'accent'
  | 'malware'
  | 'unknown'
  | 'run'

export function Badge({
  children,
  tone = 'default',
  pulse,
}: {
  children: ReactNode
  tone?: BadgeTone
  pulse?: boolean
}) {
  return (
    <span className={`badge ${tone}`}>
      {tone === 'run' || pulse ? <span className={`sq ${pulse ? 'pulse' : ''}`} /> : null}
      {children}
    </span>
  )
}

/** Honest verdict tone — unknown/missing NEVER green. */
export function verdictTone(verdict?: string | null): BadgeTone {
  const v = (verdict || '').toLowerCase()
  if (!v || v === 'unknown' || v === 'n/a' || v === 'none') return 'unknown'
  if (v.includes('malicious')) return 'malware'
  if (v.includes('suspicious') || v.includes('likely')) return 'warn'
  if (v.includes('benign') || v.includes('clean') || v.includes('goodware')) return 'ok'
  return 'unknown'
}

/** Report source tone — deterministic fallback is ALWAYS visibly red. */
export function SourceBadge({ source }: { source?: string | null }) {
  const s = (source || '').toLowerCase()
  if (!s) return <span className="src other">—</span>
  if (s.includes('deterministic_fallback') || s.includes('stub')) {
    return <span className="src fallback">{source}</span>
  }
  if (s.includes('llm') || s.includes('section_publisher')) {
    return <span className="src llm">{source}</span>
  }
  return <span className="src other">{source}</span>
}

/* ── Panels ─────────────────────────────────────────────────────────── */
export function Panel({
  title,
  actions,
  children,
  flush,
  style,
}: {
  title?: ReactNode
  actions?: ReactNode
  children: ReactNode
  flush?: boolean
  style?: React.CSSProperties
}) {
  return (
    <section className={`panel${flush ? ' flush' : ''}`} style={style}>
      {(title || actions) && (
        <header className="panel-head">
          {typeof title === 'string' ? <h2>{title}</h2> : title}
          {actions && <div className="actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  )
}

export function Grid2({ children }: { children: ReactNode }) {
  return <div className="grid2">{children}</div>
}

/* ── Page header ────────────────────────────────────────────────────── */
export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string
  subtitle?: string
  actions?: ReactNode
}) {
  return (
    <div className="page-head">
      <h1>{title}</h1>
      {subtitle && <span className="sub">{subtitle}</span>}
      {actions && <div className="actions">{actions}</div>}
    </div>
  )
}

/* ── KPI ────────────────────────────────────────────────────────────── */
export function Kpi({
  label,
  value,
  tone,
  tip,
}: {
  label: string
  value: ReactNode
  tone?: 'ok' | 'warn' | 'danger' | 'info' | 'accent'
  tip?: string
}) {
  return (
    <div className={`kpi${tone ? ` ${tone}` : ''}`} data-tip={tip}>
      <span className="v">{value}</span>
      <span className="l">{label}</span>
    </div>
  )
}

/* ── Toolbar ────────────────────────────────────────────────────────── */
export function Toolbar({ children }: { children: ReactNode }) {
  return <div className="toolbar">{children}</div>
}

export function Seg<T extends string>({
  options,
  value,
  onChange,
}: {
  options: ReadonlyArray<readonly [T, string]>
  value: T
  onChange: (v: T) => void
}) {
  return (
    <div className="seg">
      {options.map(([v, label]) => (
        <button key={v} className={v === value ? 'active' : ''} onClick={() => onChange(v)}>
          {label}
        </button>
      ))}
    </div>
  )
}

/* ── Status dot ─────────────────────────────────────────────────────── */
export function Dot({ state, tip }: { state: 'live' | 'ok' | 'warn' | 'err' | 'idle'; tip?: string }) {
  return <span className={`dot ${state}`} data-tip={tip} />
}

/* ── States ─────────────────────────────────────────────────────────── */
export function EmptyState({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="empty">
      <span className="t">{title}</span>
      {detail && <span>{detail}</span>}
    </div>
  )
}

export function ErrorBanner({ children }: { children: ReactNode }) {
  return (
    <div className="err-banner">
      <Icon.alert />
      <span>{children}</span>
    </div>
  )
}

export function NoteBanner({ children }: { children: ReactNode }) {
  return (
    <div className="note-banner">
      <Icon.check />
      <span>{children}</span>
    </div>
  )
}

export function Muted({ children }: { children: ReactNode }) {
  return <span className="muted">{children}</span>
}

export function Skeleton({ height = 120 }: { height?: number }) {
  return <div className="skeleton" style={{ height }} />
}

export function LogBox({ children }: { children: ReactNode }) {
  return <pre className="console">{children}</pre>
}

/* ── Confidence bar ─────────────────────────────────────────────────── */
export function ConfBar({ value }: { value?: number | null }) {
  if (value == null) return <span className="muted">—</span>
  const v = Math.max(0, Math.min(100, value))
  const color = v >= 90 ? 'var(--ok)' : v >= 70 ? 'var(--warn)' : 'var(--danger)'
  return (
    <span className="conf-bar">
      <span className="track">
        <span className="fill" style={{ width: `${v}%`, background: color }} />
      </span>
      <span className="v">{v}</span>
    </span>
  )
}
