const CLASSES: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

export function RiskLevelBadge({ level }: { level: string }) {
  const cls = CLASSES[level.toLowerCase()] ?? 'badge-neutral'
  return <span className={`badge ${cls}`}>{level}</span>
}
