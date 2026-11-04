import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useCampaigns } from '@/api/hooks/useCampaigns'
import type { Campaign } from '@/api/types'

const col = createColumnHelper<Campaign>()
const columns = [
  col.accessor('name', { header: 'Name' }),
  col.accessor('threat_actor_id', {
    header: 'Threat Actor',
    cell: ({ getValue }) => getValue() ?? '—',
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

export function Campaigns() {
  const { data, isLoading, error } = useCampaigns()
  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold">Campaigns</h1>
      <ErrorMessage error={error as Error | null} />
      <DataTable columns={columns} data={data?.items ?? []} isLoading={isLoading} />
    </div>
  )
}
