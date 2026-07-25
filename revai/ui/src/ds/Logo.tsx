/**
 * CADRE//RevAI brand mark — "dissection reticle".
 * A hexagonal sample held in a targeting reticle, inner layer + core node:
 * drilling down to the truth. Scales 16px → 120px.
 */
export function LogoMark({ size = 24 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      aria-hidden
      style={{ display: 'block', flexShrink: 0 }}
    >
      {/* Reticle ticks (outer) */}
      <path d="M24 2v5M24 41v5M3 24h6.3M38.7 24H45" stroke="#e3a008" strokeWidth="2" strokeLinecap="round" />
      {/* Outer hexagon — the sample */}
      <path
        d="M24 7l14.72 8.5v17L24 41 9.28 32.5v-17L24 7z"
        stroke="#e3a008"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      {/* Inner hexagon — the layer beneath */}
      <path
        d="M24 15l7.79 4.5v9L24 33l-7.79-4.5v-9L24 15z"
        stroke="#6b7480"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      {/* Core node — the finding */}
      <circle cx="24" cy="24" r="3.2" fill="#f5b92e" />
    </svg>
  )
}

/** Mark + wordmark lockup. */
export function Logo({
  size = 22,
  sub,
}: {
  size?: number
  sub?: string
}) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
      <LogoMark size={size} />
      <span style={{ display: 'inline-flex', flexDirection: 'column', lineHeight: 1.1 }}>
        <span style={{ fontWeight: 600, letterSpacing: '0.01em', color: 'var(--tx-0)', fontSize: size * 0.72 }}>
          CADRE<span style={{ color: 'var(--tx-2)', fontWeight: 400 }}>//</span>RevAI
        </span>
        {sub && (
          <span
            style={{
              fontSize: size * 0.4,
              textTransform: 'uppercase',
              letterSpacing: '0.14em',
              color: 'var(--tx-2)',
            }}
          >
            {sub}
          </span>
        )}
      </span>
    </span>
  )
}
