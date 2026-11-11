import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ErrorMessage } from '@/components/ErrorMessage'
import { RiskLevelBadge } from '@/components/RiskLevelBadge'
import { useQuickReport } from '@/api/hooks/useReports'
import type { Vulnerability } from '@/api/types'

const LEVEL_COLORS: Record<string, string> = {
  critical: 'var(--missing)', high: '#f97316', medium: '#eab308', low: '#22c55e',
}

function Kpi({ label, value, sub }: { label: string; value: number | string; sub?: string }) {
  return (
    <div className="rounded-lg p-4" style={{ background: 'var(--bg2)', border: '1px solid var(--border)' }}>
      <div className="text-2xl font-semibold tabular-nums" style={{ lineHeight: 1 }}>{value}</div>
      <div className="text-xs mt-1" style={{ color: 'var(--text2)' }}>{label}</div>
      {sub && <div className="text-xs mt-0.5" style={{ color: 'var(--text3)' }}>{sub}</div>}
    </div>
  )
}

export function QuickReport({ tenantId }: { tenantId: string }) {
  const { data, isLoading, error } = useQuickReport(tenantId)

  if (error) return <ErrorMessage error={error as Error} />
  if (isLoading) return <div className="muted text-sm">Generating report…</div>
  if (!data) return null

  const vc = createColumnHelper<Vulnerability>()
  const vulnCols = [
    vc.accessor('cve_id', { header: 'CVE' }),
    vc.accessor('cvss_score', { header: 'CVSS', cell: (c) => c.getValue()?.toFixed(1) ?? '—' }),
    vc.accessor('epss_score', { header: 'EPSS', cell: (c) => c.getValue() != null ? `${(c.getValue()! * 100).toFixed(1)}%` : '—' }),
    vc.accessor('kev_date_added', { header: 'KEV', cell: (c) => c.getValue() ? '🔴 Yes' : '—' }),
    vc.accessor('description', { header: 'Description', cell: (c) => (c.getValue() ?? '').slice(0, 80) }),
  ]

  const levels = ['critical', 'high', 'medium', 'low'] as const
  const generatedAt = new Date(data.generated_at).toLocaleString()

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm muted">Report generated {generatedAt}</p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Kpi label="Total assets" value={data.total_assets} />
        <Kpi label="Critical assets" value={data.critical_assets} sub={`${data.unscored_assets} unscored`} />
        <Kpi label="Open cases" value={data.open_cases} sub={`${data.sla_breached_cases} SLA breached`} />
        <Kpi label="KEV vulnerabilities" value={data.kev_vulnerabilities} />
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Kpi label="Leaked identities" value={data.leaks_total} />
        <Kpi label="Dark web findings (new)" value={data.darkweb_findings_new} />
        <Kpi label="SLA at risk" value={data.sla_at_risk_cases} />
        <div className="rounded-lg p-4" style={{ background: 'var(--bg2)', border: '1px solid var(--border)' }}>
          <div className="text-xs font-semibold mb-2" style={{ color: 'var(--text2)' }}>Assets by level</div>
          <div className="flex gap-2 flex-wrap">
            {levels.map((l) => (
              <div key={l} className="flex items-center gap-1 text-xs">
                <span className="inline-block w-2 h-2 rounded-sm" style={{ background: LEVEL_COLORS[l] }} />
                <span style={{ color: 'var(--text2)' }}>{l}</span>
                <span className="font-semibold tabular-nums">{data.assets_by_level[l]}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top assets */}
      <div>
        <h3 className="text-xs font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--text3)' }}>
          Top {data.top_assets.length} highest-risk assets
        </h3>
        <div className="space-y-1">
          {data.top_assets.map((a) => (
            <div key={a.asset_id} className="flex items-center gap-3 text-sm rounded px-3 py-2" style={{ background: 'var(--bg2)' }}>
              <RiskLevelBadge level={a.level} />
              <span className="font-medium">{a.hostname ?? a.ip ?? a.asset_id.slice(0, 8)}</span>
              <span className="muted text-xs">{a.ip ?? ''}</span>
              <span className="ml-auto font-semibold tabular-nums">{a.value.toFixed(2)}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Top vulnerabilities */}
      {data.top_vulnerabilities.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--text3)' }}>
            Top active vulnerabilities
          </h3>
          <DataTable columns={vulnCols} data={data.top_vulnerabilities} isLoading={false} />
        </div>
      )}

      {/* Risk trend */}
      {data.risk_trend.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--text3)' }}>
            30-day risk trend (avg score)
          </h3>
          <div className="flex items-end gap-0.5 h-16">
            {data.risk_trend.map((p) => {
              const pct = Math.min(p.avg_score / 10, 1)
              return (
                <div
                  key={p.date}
                  title={`${p.date}: ${p.avg_score.toFixed(2)}`}
                  className="flex-1 rounded-t"
                  style={{ height: `${Math.max(pct * 100, 4)}%`, background: 'var(--accent)', opacity: 0.6 }}
                />
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
