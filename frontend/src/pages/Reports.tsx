import { createColumnHelper } from '@tanstack/react-table'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from 'recharts'
import { DataTable } from '@/components/DataTable'
import { ErrorMessage } from '@/components/ErrorMessage'
import { RiskLevelBadge } from '@/components/RiskLevelBadge'
import { RiskGauge } from '@/components/RiskGauge'
import { useQuickReport } from '@/api/hooks/useReports'
import { downloadCsv, quickReportCsv } from '@/api/reportCsv'
import type { QuickReport, Vulnerability } from '@/api/types'

const col = createColumnHelper<Vulnerability>()
const vulnColumns = [
  col.accessor('cve_id', { header: 'CVE' }),
  col.accessor('cvss_score', {
    header: 'CVSS',
    cell: ({ getValue }) => getValue()?.toFixed(1) ?? '—',
  }),
  col.accessor('epss_score', {
    header: 'EPSS',
    cell: ({ getValue }) => {
      const v = getValue()
      return v != null ? `${(v * 100).toFixed(1)}%` : '—'
    },
  }),
  col.accessor('kev_date_added', {
    header: 'KEV Date',
    cell: ({ getValue }) => getValue() ?? '—',
  }),
]

type TopAsset = QuickReport['top_assets'][number]
const assetCol = createColumnHelper<TopAsset>()
const assetColumns = [
  assetCol.display({ id: 'asset', header: 'Asset', cell: (i) => i.row.original.hostname ?? i.row.original.ip ?? i.row.original.asset_id.slice(0, 8) }),
  assetCol.accessor('ip', { header: 'IP', cell: ({ getValue }) => getValue() ?? '—' }),
  assetCol.accessor('value', { header: 'Score', cell: ({ getValue }) => getValue().toFixed(2) }),
  assetCol.accessor('level', { header: 'Level', cell: ({ getValue }) => <RiskLevelBadge level={getValue()} /> }),
]

const LEVELS = ['critical', 'high', 'medium', 'low'] as const
const LEVEL_COLOR: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }

function LevelBar({ counts, unscored }: { counts: QuickReport['assets_by_level']; unscored: number }) {
  const total = LEVELS.reduce((n, l) => n + counts[l], 0) + unscored
  if (total === 0) return <p className="muted text-sm">No assets yet.</p>
  return (
    <div>
      <div className="flex h-3 overflow-hidden rounded" role="img" aria-label="Assets by risk level">
        {LEVELS.map((l) => counts[l] > 0 && (
          <div key={l} style={{ width: `${(counts[l] / total) * 100}%`, background: LEVEL_COLOR[l] }} />
        ))}
        {unscored > 0 && <div style={{ width: `${(unscored / total) * 100}%`, background: '#64748b' }} />}
      </div>
      <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {LEVELS.map((l) => <li key={l}>{l}: <strong>{counts[l]}</strong></li>)}
        <li>not scored: <strong>{unscored}</strong></li>
      </ul>
    </div>
  )
}

function KpiCard({ label, value, warn }: { label: string; value: number; warn?: boolean }) {
  return (
    <div className="card" style={warn && value > 0 ? { borderColor: '#ef4444' } : undefined}>
      <p className="mono text-2xl font-medium">{value}</p>
      <p className="card-title mb-0 mt-1">{label}</p>
    </div>
  )
}

// Plain facts already in the report, turned into sentences. No model, no guessing: each line
// only fires on a number already shown above, so it can never say something the KPIs don't.
function reasoning(data: QuickReport): string[] {
  const items: string[] = []
  if (data.kev_vulnerabilities > 0) {
    items.push(`${data.kev_vulnerabilities} vulnerabilit${data.kev_vulnerabilities === 1 ? 'y' : 'ies'} in CISA KEV: active exploitation confirmed in the wild.`)
  }
  if (data.critical_assets > 0) {
    items.push(`${data.critical_assets} asset${data.critical_assets === 1 ? '' : 's'} at critical risk level.`)
  }
  if (data.sla_breached_cases > 0) {
    items.push(`${data.sla_breached_cases} case${data.sla_breached_cases === 1 ? '' : 's'} past SLA.`)
  }
  if (data.leaks_total > 0) {
    items.push(`${data.leaks_total} leaked identit${data.leaks_total === 1 ? 'y' : 'ies'} on record.`)
  }
  if (data.darkweb_findings_new > 0) {
    items.push(`${data.darkweb_findings_new} new dark web finding${data.darkweb_findings_new === 1 ? '' : 's'} not yet reviewed.`)
  }
  return items
}

export function Reports({ tenantId }: { tenantId: string }) {
  const { data, isLoading, error } = useQuickReport(tenantId)
  return (
    <div className="space-y-4">
      <ErrorMessage error={error as Error | null} />
      {data && (
        <>
          <div className="no-print flex items-center justify-between gap-3">
            <p className="muted text-xs">Generated {new Date(data.generated_at).toLocaleString()}</p>
            <div className="flex gap-2">
              <button className="btn btn-ghost" onClick={() => downloadCsv('meitaka-quick-report.csv', quickReportCsv(data))}>
                Download CSV
              </button>
              <button className="btn btn-ghost" onClick={() => window.print()}>Print / PDF</button>
            </div>
          </div>
          <div className="card">
            <div className="flex items-center gap-4">
              {data.top_assets[0] ? (
                <RiskGauge value={data.top_assets[0].value} level={data.top_assets[0].level} />
              ) : (
                <RiskGauge value={0} level="low" />
              )}
              <div className="flex-1">
                <p className="muted text-xs uppercase tracking-wide">Highest-risk asset</p>
                <p className="text-lg font-medium">
                  {data.top_assets[0]
                    ? data.top_assets[0].hostname ?? data.top_assets[0].ip ?? data.top_assets[0].asset_id.slice(0, 8)
                    : 'No assets scored yet'}
                </p>
                {data.top_assets[0] && <RiskLevelBadge level={data.top_assets[0].level} />}
              </div>
            </div>
            {reasoning(data).length > 0 && (
              <div className="mt-3 border-t pt-3" style={{ borderColor: 'var(--border)' }}>
                <h2 className="card-title">Why this needs attention</h2>
                <ul className="space-y-1 text-sm">
                  {reasoning(data).map((r) => <li key={r}>• {r}</li>)}
                </ul>
              </div>
            )}
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <KpiCard label="Total Assets" value={data.total_assets} />
            <KpiCard label="Critical Assets" value={data.critical_assets} />
            <KpiCard label="Open Cases" value={data.open_cases} />
            <KpiCard label="Top Vulnerabilities" value={data.top_vulnerabilities.length} />
            <KpiCard label="Cases Past SLA" value={data.sla_breached_cases} warn />
            <KpiCard label="Vulnerabilities in KEV" value={data.kev_vulnerabilities} warn />
            <KpiCard label="Leaked Emails" value={data.leaks_total} />
            <KpiCard label="New Dark Web Findings" value={data.darkweb_findings_new} />
          </div>
          <div className="card">
            <h2 className="card-title">Assets by risk level</h2>
            <LevelBar counts={data.assets_by_level} unscored={data.unscored_assets} />
          </div>
          <div>
            <h2 className="card-title">Top assets at risk</h2>
            <DataTable columns={assetColumns} data={data.top_assets} isLoading={isLoading} />
          </div>
          <div className="card">
            <h2 className="card-title">Risk Trend (30 days)</h2>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={data.risk_trend}>
                <XAxis dataKey="date" tick={{ fill: '#94a3b8', fontSize: 11 }} stroke="#334155" />
                <YAxis domain={[0, 1]} tick={{ fill: '#94a3b8', fontSize: 11 }} stroke="#334155" />
                <Tooltip
                  formatter={(v: number) => v.toFixed(3)}
                  contentStyle={{ background: '#131928', border: '1px solid #334155', color: '#e2e8f0' }}
                />
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,.07)" />
                <Line
                  type="monotone"
                  dataKey="avg_score"
                  stroke="#52b6ff"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div>
            <h2 className="card-title">Top Vulnerabilities</h2>
            <DataTable
              columns={vulnColumns}
              data={data.top_vulnerabilities}
              isLoading={isLoading}
            />
          </div>
        </>
      )}
      {!data && !isLoading && (
        <DataTable columns={vulnColumns} data={[]} isLoading={false} />
      )}
    </div>
  )
}
