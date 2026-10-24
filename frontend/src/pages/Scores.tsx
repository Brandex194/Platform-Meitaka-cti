import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { RiskLevelBadge } from '@/components/RiskLevelBadge'
import { useScores } from '@/api/hooks/useScores'
import type { Score } from '@/api/types'

const columns: ColumnDef<Score, any>[] = [
  {
    header: 'Asset',
    accessorKey: 'asset_id',
    cell: (c) => (c.getValue<string | null>() ?? '').slice(0, 8),
  },
  { header: 'Type', accessorKey: 'score_type' },
  { header: 'Value', accessorKey: 'value', cell: (c) => c.getValue<number>().toFixed(2) },
  {
    header: 'Level',
    accessorKey: 'level',
    cell: (c) => <RiskLevelBadge level={c.getValue<string>()} />,
  },
  { header: 'Computed', accessorKey: 'computed_at' },
]

export function Scores({ tenantId }: { tenantId: string }) {
  const { data, isLoading } = useScores(tenantId)
  return (
    <div className="p-6">
      <DataTable<Score> data={data?.items ?? []} columns={columns} isLoading={isLoading} />
    </div>
  )
}
