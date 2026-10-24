import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useDashboard } from '@/api/hooks/useDashboard'
import type { CorrelationEvent } from '@/api/types'

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm">
      <p className="text-3xl font-bold">{value}</p>
      <p className="text-sm text-gray-500">{label}</p>
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
      <span className={c.getValue<boolean>() ? 'text-green-600' : 'text-red-600'}>
        {c.getValue<boolean>() ? 'Yes' : 'No'}
      </span>
    ),
  },
  { header: 'Created', accessorKey: 'created_at' },
]

export function Dashboard({ tenantId }: { tenantId: string }) {
  const { data, isLoading, error } = useDashboard(tenantId)

  return (
    <div className="space-y-6 p-6">
      <ErrorMessage error={error} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Open Cases" value={data?.open_cases ?? 0} />
        <StatCard label="Critical Scores" value={data?.critical_scores ?? 0} />
        <StatCard label="Active Exposures" value={data?.active_exposures ?? 0} />
        <StatCard label="Recent Events" value={data?.recent_events.length ?? 0} />
      </div>
      <div style={{ height: 200 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data?.scores_by_level ?? []}>
            <XAxis dataKey="level" />
            <YAxis />
            <Tooltip />
            <Bar dataKey="count" />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <DataTable<CorrelationEvent>
        data={data?.recent_events ?? []}
        columns={eventColumns}
        isLoading={isLoading}
      />
    </div>
  )
}
