import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { useExposure, usePatchExposure } from '@/api/hooks/useExposure'
import { useAuthStore } from '@/auth/store'
import type { ExposureMatch } from '@/api/types'

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === 'active'
      ? 'bg-orange-100 text-orange-800'
      : status === 'resolved'
        ? 'bg-green-100 text-green-800'
        : 'bg-gray-100 text-gray-600'
  return (
    <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${cls}`}>
      {status}
    </span>
  )
}

export function Exposure({ tenantId }: { tenantId: string }) {
  const { data, isLoading } = useExposure(tenantId)
  const patchMutation = usePatchExposure(tenantId)
  const { hasRole } = useAuthStore()
  const canMutate = hasRole('analyst') || hasRole('tenant_admin') || hasRole('super_admin')

  const columns: ColumnDef<ExposureMatch, any>[] = [
    {
      header: 'Status',
      accessorKey: 'status',
      cell: (c) => <StatusBadge status={c.getValue<string>()} />,
    },
    {
      header: 'EPSS',
      accessorKey: 'epss_score',
      cell: (c) => c.getValue<number | null>()?.toFixed(2) ?? '—',
    },
    { header: 'Updated', accessorKey: 'updated_at' },
    ...(canMutate
      ? [
          {
            id: 'actions',
            header: 'Actions',
            cell: (info: { row: { original: ExposureMatch } }) => (
              <button
                className="rounded bg-green-600 px-2 py-1 text-xs text-white"
                onClick={() =>
                  patchMutation.mutate({ id: info.row.original.id, status: 'resolved' })
                }
                disabled={patchMutation.isPending}
              >
                Resolve
              </button>
            ),
          } as ColumnDef<ExposureMatch, any>,
        ]
      : []),
  ]

  return (
    <div className="p-6">
      <DataTable<ExposureMatch> data={data?.items ?? []} columns={columns} isLoading={isLoading} />
    </div>
  )
}
