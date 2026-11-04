import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useObservations } from '@/api/hooks/useObservations'
import type { Observation } from '@/api/types'

const col = createColumnHelper<Observation>()
const columns = [
  col.accessor('event_type', { header: 'Event Type' }),
  col.accessor('payload', {
    id: 'source',
    header: 'Source',
    cell: ({ getValue }) => (getValue() as any)?.source ?? '—',
  }),
  col.accessor('payload', {
    id: 'context',
    header: 'Context',
    cell: ({ getValue }) => (getValue() as any)?.context ?? '—',
  }),
  col.accessor('created_at', { header: 'Detected' }),
]

export function DarkWeb({ tenantId }: { tenantId: string }) {
  const { data, isLoading, error } = useObservations(tenantId, 'darkweb')
  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">Dark Web</h1>
      <p className="mb-4 text-sm text-gray-500">
        ML classifier available in Phase 3. Showing raw dark web observations.
      </p>
      <ErrorMessage error={error as Error | null} />
      <DataTable columns={columns} data={data?.items ?? []} isLoading={isLoading} />
    </div>
  )
}
