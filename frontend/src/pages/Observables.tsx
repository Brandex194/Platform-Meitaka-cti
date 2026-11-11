import { useState } from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ConfirmModal } from '@/components/ConfirmModal'
import { ErrorMessage } from '@/components/ErrorMessage'
import { FormModal } from '@/components/FormModal'
import { useAuthStore } from '@/auth/store'
import { useEnrichIndicator, useEnrichments } from '@/api/hooks/useIntegrations'
import {
  useIndicators,
  useCreateIndicator,
  useDeleteIndicator,
  type IndicatorType,
} from '@/api/hooks/useIndicators'
import type { Enrichment, Indicator } from '@/api/types'

const col = createColumnHelper<Indicator>()

const ENRICHABLE = ['ip', 'domain', 'url', 'hash']

/** One line for the VirusTotal verdict: detections out of the engines that answered. */
function Verdict({ e }: { e: Enrichment | undefined }) {
  if (!e) return <span className="muted">—</span>
  if (e.status === 'not_found') return <span className="badge badge-neutral">unknown to VT</span>
  const bad = (e.malicious ?? 0) + (e.suspicious ?? 0)
  const total = bad + (e.harmless ?? 0) + (e.undetected ?? 0)
  const cls = (e.malicious ?? 0) > 0 ? 'badge-critical' : bad > 0 ? 'badge-medium' : 'badge-low'
  const label = `${bad}/${total}`
  return e.permalink ? (
    <a className={`badge ${cls}`} href={e.permalink} target="_blank" rel="noopener noreferrer" title="Open on VirusTotal">
      {label}
    </a>
  ) : (
    <span className={`badge ${cls}`}>{label}</span>
  )
}

const TYPES: IndicatorType[] = ['ip', 'domain', 'url', 'hash', 'email']

interface FormState {
  ioc_type: IndicatorType
  value: string
  confidence: string // percent, optional
}
const EMPTY: FormState = { ioc_type: 'ip', value: '', confidence: '' }

/** Percent typed by the user -> 0..1 for the API; null when empty or not a number in range. */
function parseConfidence(text: string): number | null | undefined {
  if (!text.trim()) return null
  const n = Number(text)
  if (!Number.isFinite(n) || n < 0 || n > 100) return undefined
  return n / 100
}

export function Observables({ tenantId }: { tenantId: string }) {
  const { hasRole } = useAuthStore()
  const [typeFilter, setTypeFilter] = useState('')
  const { data, isLoading, error } = useIndicators(tenantId)
  const create = useCreateIndicator(tenantId)
  const remove = useDeleteIndicator(tenantId)
  const enrich = useEnrichIndicator(tenantId)
  const enrichments = useEnrichments(tenantId)
  const verdicts = new Map((enrichments.data?.items ?? []).map((e) => [e.indicator_id, e]))
  const [form, setForm] = useState<FormState | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)

  const canWrite = hasRole('analyst') || hasRole('tenant_admin') || hasRole('super_admin')
  const rows = typeFilter
    ? (data?.items ?? []).filter((i) => i.ioc_type === typeFilter)
    : (data?.items ?? [])
  const types = [...new Set((data?.items ?? []).map((i) => i.ioc_type))].sort()
  const confidence = form ? parseConfidence(form.confidence) : null

  const close = () => {
    setForm(null)
    create.reset()
  }

  const columns = [
    col.accessor('ioc_type', {
      header: 'Type',
      cell: ({ getValue }) => <span className="badge badge-info">{getValue()}</span>,
    }),
    col.accessor('value', { header: 'Value' }),
    col.accessor('confidence', {
      header: 'Confidence',
      cell: ({ getValue }) => {
        const v = getValue()
        return v != null ? `${(v * 100).toFixed(1)}%` : '—'
      },
    }),
    col.accessor('tenant_id', {
      header: 'Source',
      cell: ({ getValue }) =>
        getValue() ? <span className="badge badge-info">yours</span> : <span className="badge badge-neutral">feed</span>,
    }),
    col.display({
      id: 'vt',
      header: 'VirusTotal',
      cell: ({ row }) => <Verdict e={verdicts.get(row.original.id)} />,
    }),
    col.accessor('created_at', { header: 'Added' }),
    ...(canWrite
      ? [
          col.display({
            id: 'actions',
            header: 'Actions',
            cell: ({ row }) => (
              <div className="flex gap-3">
                {ENRICHABLE.includes(row.original.ioc_type) && (
                  <button
                    className="text-xs link"
                    disabled={enrich.isPending}
                    onClick={() => enrich.mutate(row.original.id)}
                  >
                    {verdicts.has(row.original.id) ? 'Refresh' : 'Enrich'}
                  </button>
                )}
                {row.original.tenant_id === tenantId && (
                  <button className="text-xs link-danger" onClick={() => setDeleteId(row.original.id)}>
                    Delete
                  </button>
                )}
              </div>
            ),
          }),
        ]
      : []),
  ]

  return (
    <div>
      <div className="mb-3 flex items-center justify-end gap-2">
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="field-inline"
          aria-label="Filter by type"
        >
          <option value="">All types</option>
          {types.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        {canWrite && (
          <button className="btn btn-primary" onClick={() => setForm(EMPTY)}>
            Add observable
          </button>
        )}
      </div>
      <ErrorMessage error={(error ?? remove.error ?? enrich.error) as Error | null} />
      <DataTable columns={columns} data={rows} isLoading={isLoading} />

      {form && (
        <FormModal
          title="Add observable"
          submitLabel="Add"
          onSubmit={() =>
            create.mutate(
              { ioc_type: form.ioc_type, value: form.value.trim(), confidence },
              { onSuccess: close },
            )
          }
          onCancel={close}
          canSubmit={form.value.trim().length > 0 && confidence !== undefined}
          isPending={create.isPending}
          error={create.error as Error | null}
        >
          <select
            className="field"
            aria-label="Type"
            value={form.ioc_type}
            onChange={(e) => setForm({ ...form, ioc_type: e.target.value as IndicatorType })}
          >
            {TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <input
            className="field"
            placeholder="Value (IP, domain, URL, hash or email)"
            aria-label="Value"
            value={form.value}
            onChange={(e) => setForm({ ...form, value: e.target.value })}
          />
          <input
            className="field"
            placeholder="Confidence 0-100 (optional)"
            aria-label="Confidence"
            inputMode="decimal"
            value={form.confidence}
            onChange={(e) => setForm({ ...form, confidence: e.target.value })}
          />
          {confidence === undefined && (
            <p className="text-xs" style={{ color: 'var(--critical)' }}>
              Confidence must be a number from 0 to 100.
            </p>
          )}
        </FormModal>
      )}

      {deleteId && (
        <ConfirmModal
          title="Delete observable"
          message="This cannot be undone."
          onConfirm={() => { remove.mutate(deleteId); setDeleteId(null) }}
          onCancel={() => setDeleteId(null)}
        />
      )}
    </div>
  )
}
