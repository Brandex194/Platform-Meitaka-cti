import { useState, useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { useCorrelationEvents } from '@/api/hooks/useAnalysis'
import type { CorrelationEvent } from '@/api/types'

const columns: ColumnDef<CorrelationEvent, any>[] = [
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
  { header: 'Resolved', accessorKey: 'resolved_at' },
  { header: 'Created', accessorKey: 'created_at' },
]

export function Analysis({ tenantId }: { tenantId: string }) {
  const { data, isLoading } = useCorrelationEvents(tenantId)
  const [activeOnly, setActiveOnly] = useState(false)

  const rows = useMemo(
    () => (activeOnly ? (data?.items ?? []).filter((e) => e.is_active) : (data?.items ?? [])),
    [data, activeOnly],
  )

  return (
    <div className="space-y-4 p-6">
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={activeOnly}
          onChange={(e) => setActiveOnly(e.target.checked)}
        />
        Active only
      </label>
      <DataTable<CorrelationEvent> data={rows} columns={columns} isLoading={isLoading} />
    </div>
  )
}
