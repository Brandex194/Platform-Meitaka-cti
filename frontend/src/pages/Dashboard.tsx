import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useDashboard } from '@/api/hooks/useDashboard'
import type { CorrelationEvent } from '@/api/types'

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="card">
      <p className="mono text-3xl font-medium">{value}</p>
      <p className="card-title mb-0 mt-1">{label}</p>
    </div>
  )
}

const eventColumns: ColumnDef<CorrelationEvent, any>[] = [
  { header: 'Rule', accessorKey: 'rule_name' },
  {
    header: 'Score',
    accessorKey: 's_context',
    cell: (c) => c.getValue<number | null>()?.toFixed(2) ?? '—',
  },
  {
    header: 'Active',
    accessorKey: 'is_active',
    cell: (c) => (
      <span className={c.getValue<boolean>() ? 'text-[var(--low)]' : 'text-[var(--critical)]'}>
        {c.getValue<boolean>() ? 'Yes' : 'No'}
      </span>
    ),
  },
  { header: 'Created', accessorKey: 'created_at' },
]

export function Dashboard({ tenantId }: { tenantId: string }) {
  const { data, isLoading, error } = useDashboard(tenantId)

  return (
    <div className="space-y-4">
      <ErrorMessage error={error} />
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <StatCard label="Open Cases" value={data?.open_cases ?? 0} />
        <StatCard label="Critical Scores" value={data?.critical_scores ?? 0} />
        <StatCard label="Active Exposures" value={data?.active_exposures ?? 0} />
        <StatCard label="Recent Events" value={data?.recent_events?.length ?? 0} />
      </div>
      <div className="card">
        <h2 className="card-title">Score per livello di rischio</h2>
        <div style={{ height: 200 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data?.scores_by_level ?? []}>
              <XAxis dataKey="level" tick={{ fill: '#94a3b8', fontSize: 11 }} stroke="#334155" />
              <YAxis allowDecimals={false} tick={{ fill: '#94a3b8', fontSize: 11 }} stroke="#334155" />
              <Tooltip
                cursor={{ fill: 'rgba(255,255,255,.04)' }}
                contentStyle={{ background: '#131928', border: '1px solid #334155', color: '#e2e8f0' }}
              />
              <Bar dataKey="count" fill="#52b6ff" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
      <DataTable<CorrelationEvent>
        data={data?.recent_events ?? []}
        columns={eventColumns}
        isLoading={isLoading}
      />
    </div>
  )
}
