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
import { useQuickReport } from '@/api/hooks/useReports'
import type { Vulnerability } from '@/api/types'

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

function KpiCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4">
      <p className="text-sm text-gray-500">{label}</p>
      <p className="mt-1 text-2xl font-bold">{value}</p>
    </div>
  )
}

export function Reports({ tenantId }: { tenantId: string }) {
  const { data, isLoading, error } = useQuickReport(tenantId)
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Reports</h1>
      <ErrorMessage error={error as Error | null} />
      {data && (
        <>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <KpiCard label="Total Assets" value={data.total_assets} />
            <KpiCard label="Critical Assets" value={data.critical_assets} />
            <KpiCard label="Open Cases" value={data.open_cases} />
            <KpiCard label="Top Vulnerabilities" value={data.top_vulnerabilities.length} />
          </div>
          <div className="rounded-lg border border-gray-200 bg-white p-4">
            <h2 className="mb-3 text-sm font-semibold text-gray-600">Risk Trend (30 days)</h2>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={data.risk_trend}>
                <XAxis dataKey="date" tick={{ fontSize: 11 }} />
                <YAxis domain={[0, 1]} tick={{ fontSize: 11 }} />
                <Tooltip formatter={(v: number) => v.toFixed(3)} />
                <CartesianGrid strokeDasharray="3 3" />
                <Line
                  type="monotone"
                  dataKey="avg_score"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div>
            <h2 className="mb-3 text-sm font-semibold text-gray-600">Top Vulnerabilities</h2>
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
