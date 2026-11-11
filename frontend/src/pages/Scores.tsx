import { useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { RiskLevelBadge } from '@/components/RiskLevelBadge'
import { ScoreExplanationPanel } from '@/components/ScoreExplanationPanel'
import { useScores } from '@/api/hooks/useScores'
import type { Score } from '@/api/types'

export function Scores({ tenantId }: { tenantId: string }) {
  const { data, isLoading } = useScores(tenantId)
  const [assetId, setAssetId] = useState<string | null>(null)

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
    {
      header: 'Why',
      id: 'why',
      cell: (c) =>
        c.row.original.asset_id ? (
          <button className="btn btn-ghost" onClick={() => setAssetId(c.row.original.asset_id)}>
            Explain
          </button>
        ) : null,
    },
  ]

  return (
    <div className="space-y-4">
      {assetId && (
        <ScoreExplanationPanel tenantId={tenantId} assetId={assetId} onClose={() => setAssetId(null)} />
      )}
      <DataTable<Score> data={data?.items ?? []} columns={columns} isLoading={isLoading} />
    </div>
  )
}
