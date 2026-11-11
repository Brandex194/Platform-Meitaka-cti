import { useState, useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { useAssets, usePatchAsset, type AssetContextPatch } from '@/api/hooks/useAssets'
import { useAuthStore } from '@/auth/store'
import type { Asset } from '@/api/types'

// Architettura §5.2: the factor each choice multiplies the score by lives in the active ScoreRule.
const EXPOSURE = [
  { value: 'internet', label: 'Internet' },
  { value: 'dmz', label: 'DMZ' },
  { value: 'internal', label: 'Interno' },
]
const IMPACT = [
  { value: 'critical', label: 'Dati sensibili / essenziale' },
  { value: 'business', label: 'Business critical' },
  { value: 'low', label: 'Non critico' },
]
const WRITERS = ['super_admin', 'tenant_admin', 'api_user']

function ContextSelect({
  label,
  value,
  options,
  disabled,
  onChange,
}: {
  label: string
  value: string | null
  options: { value: string; label: string }[]
  disabled: boolean
  onChange: (v: string | null) => void
}) {
  return (
    <select
      aria-label={label}
      className="field-inline"
      value={value ?? ''}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value || null)}
    >
      <option value="">Non classificato</option>
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  )
}

export function Assets({ tenantId }: { tenantId: string }) {
  const { data, isLoading } = useAssets(tenantId)
  const patch = usePatchAsset(tenantId)
  const { hasRole } = useAuthStore()
  const canEdit = WRITERS.some((r) => hasRole(r))
  const [filter, setFilter] = useState('')

  const columns = useMemo<ColumnDef<Asset, any>[]>(() => {
    const save = (id: string, body: AssetContextPatch) => patch.mutate({ id, ...body })
    return [
      { header: 'Hostname', accessorKey: 'hostname' },
      { header: 'IP', accessorKey: 'ip' },
      {
        header: 'Esposizione',
        accessorKey: 'exposure',
        cell: (c) => (
          <ContextSelect
            label={`Esposizione di ${c.row.original.hostname ?? c.row.original.id}`}
            value={c.row.original.exposure}
            options={EXPOSURE}
            disabled={!canEdit || patch.isPending}
            onChange={(v) => save(c.row.original.id, { exposure: v as Asset['exposure'] })}
          />
        ),
      },
      {
        header: 'Impatto',
        accessorKey: 'impact',
        cell: (c) => (
          <ContextSelect
            label={`Impatto di ${c.row.original.hostname ?? c.row.original.id}`}
            value={c.row.original.impact}
            options={IMPACT}
            disabled={!canEdit || patch.isPending}
            onChange={(v) => save(c.row.original.id, { impact: v as Asset['impact'] })}
          />
        ),
      },
      { header: 'Created', accessorKey: 'created_at' },
    ]
  }, [canEdit, patch])

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
    <div className="space-y-3">
      <input
        className="field-inline"
        placeholder="Filter by hostname…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      <DataTable<Asset> data={rows} columns={columns} isLoading={isLoading} />
      <p className="text-xs muted">
        Esposizione e impatto pesano sul rischio dal prossimo ricalcolo dello score. Un asset non
        classificato conta come esposto su internet e critico.
      </p>
    </div>
  )
}
