import { useState, useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { useAssets } from '@/api/hooks/useAssets'
import type { Asset } from '@/api/types'

const columns: ColumnDef<Asset, any>[] = [
  { header: 'Hostname', accessorKey: 'hostname' },
  { header: 'IP', accessorKey: 'ip' },
  { header: 'Created', accessorKey: 'created_at' },
]

export function Assets({ tenantId }: { tenantId: string }) {
  const { data, isLoading } = useAssets(tenantId)
  const [filter, setFilter] = useState('')

  const rows = useMemo(
    () =>
      filter
        ? (data?.items ?? []).filter((a) =>
            (a.hostname ?? '').toLowerCase().includes(filter.toLowerCase()),
          )
        : (data?.items ?? []),
    [data, filter],
  )

  return (
    <div className="space-y-4 p-6">
      <input
        className="rounded border px-3 py-1.5 text-sm"
        placeholder="Filter by hostname…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      <DataTable<Asset> data={rows} columns={columns} isLoading={isLoading} />
    </div>
  )
}
