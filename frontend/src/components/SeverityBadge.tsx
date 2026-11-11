const CLASSES: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = CLASSES[severity.toLowerCase()] ?? 'badge-neutral'
  return <span className={`badge ${cls}`}>{severity}</span>
}
