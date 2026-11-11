import type { SlaStatus } from '@/api/types'

const LOOK: Record<SlaStatus, { cls: string; label: string }> = {
  on_track: { cls: 'badge-low', label: 'on track' },
  at_risk: { cls: 'badge-medium', label: 'at risk' },
  breached: { cls: 'badge-critical', label: 'breached' },
  met: { cls: 'badge-info', label: 'met' },
  none: { cls: 'badge-neutral', label: 'no SLA' },
}

export function SlaBadge({ status }: { status: SlaStatus }) {
  const { cls, label } = LOOK[status] ?? LOOK.none
  return <span className={`badge ${cls}`}>{label}</span>
}
