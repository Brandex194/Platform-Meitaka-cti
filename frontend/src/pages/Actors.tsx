import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useActors } from '@/api/hooks/useActors'
import type { ThreatActor } from '@/api/types'

const col = createColumnHelper<ThreatActor>()
const columns = [
  col.accessor('name', { header: 'Name' }),
  col.accessor('aliases', {
    header: 'Aliases',
    cell: ({ getValue }) => (getValue() ?? []).join(', ') || '—',
  }),
  col.accessor('description', {
    header: 'Description',
    cell: ({ getValue }) => {
      const v = getValue()
      if (!v) return '—'
      return v.length > 80 ? v.slice(0, 80) + '…' : v
    },
  }),
  col.accessor('created_at', { header: 'Added' }),
]

export function Actors() {
  const { data, isLoading, error } = useActors()
  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">Threat Actors</h1>
      <ErrorMessage error={error as Error | null} />
      <DataTable columns={columns} data={data?.items ?? []} isLoading={isLoading} />
    </div>
  )
}
