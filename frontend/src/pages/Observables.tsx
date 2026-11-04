import { useState } from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { SeverityBadge } from '@/components/SeverityBadge'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useIndicators } from '@/api/hooks/useIndicators'
import type { Indicator } from '@/api/types'

const col = createColumnHelper<Indicator>()
const columns = [
  col.accessor('ioc_type', {
    header: 'Type',
    cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
  }),
  col.accessor('value', { header: 'Value' }),
  col.accessor('confidence', {
    header: 'Confidence',
    cell: ({ getValue }) => {
      const v = getValue()
      return v != null ? `${(v * 100).toFixed(1)}%` : '—'
    },
  }),
  col.accessor('created_at', { header: 'Added' }),
]

export function Observables({ tenantId }: { tenantId: string }) {
  const [typeFilter, setTypeFilter] = useState('')
  const { data, isLoading, error } = useIndicators(tenantId)
  const rows = typeFilter
    ? (data?.items ?? []).filter((i) => i.ioc_type === typeFilter)
    : (data?.items ?? [])
  const types = [...new Set((data?.items ?? []).map((i) => i.ioc_type))].sort()

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Observables</h1>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="rounded border border-gray-300 px-3 py-1.5 text-sm"
        >
          <option value="">All types</option>
          {types.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>
      <ErrorMessage error={error as Error | null} />
      <DataTable columns={columns} data={rows} isLoading={isLoading} />
    </div>
  )
}
