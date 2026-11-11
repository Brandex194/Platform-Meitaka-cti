const LEVEL_COLOR: Record<string, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
  info: 'var(--info)',
}

export function RiskGauge({ value, level, size = 86 }: { value: number; level: string; size?: number }) {
  const stroke = Math.max(4, size * 0.07)
  const r = size / 2 - stroke
  const circ = 2 * Math.PI * r
  const off = circ - Math.max(0, Math.min(1, value)) * circ
  const color = LEVEL_COLOR[level.toLowerCase()] ?? 'var(--text3)'
  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }} role="img" aria-label={`Risk score ${value.toFixed(2)}, ${level}`}>
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,.08)" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={circ.toFixed(2)}
          strokeDashoffset={off.toFixed(2)}
          strokeLinecap="round"
        />
      </svg>
      <div
        style={{
          position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
        }}
      >
        <span className="mono" style={{ fontSize: size * 0.26, fontWeight: 600, color, lineHeight: 1 }}>
          {value.toFixed(2)}
        </span>
        <span className="muted" style={{ fontSize: size * 0.1, textTransform: 'uppercase', letterSpacing: '.05em' }}>
          /1.0
        </span>
      </div>
    </div>
  )
}
