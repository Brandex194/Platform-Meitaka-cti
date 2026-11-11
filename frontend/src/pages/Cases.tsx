import { useState } from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { SeverityBadge } from '@/components/SeverityBadge'
import { ConfirmModal } from '@/components/ConfirmModal'
import { ErrorMessage } from '@/components/ErrorMessage'
import { SlaBadge } from '@/components/SlaBadge'
import { CaseDetail } from '@/components/CaseDetail'
import { useAuthStore } from '@/auth/store'
import { useCases, useCreateCase, useUpdateCase, useDeleteCase } from '@/api/hooks/useCases'
import type { Case } from '@/api/types'

const col = createColumnHelper<Case>()

interface CaseFormState {
  title: string
  description: string
  severity: string
  status: string
}

const STATUS_LABEL: Record<string, string> = {
  open: 'Open',
  in_progress: 'In analysis',
  closed: 'Closed',
  false_positive: 'False positive',
}
const STATUS_BADGE: Record<string, string> = {
  open: 'badge-high',
  in_progress: 'badge-info',
  closed: 'badge-low',
  false_positive: 'badge-neutral',
}
const FILTERS: [string, string][] = [
  ['', 'All'],
  ['open', 'Open'],
  ['in_progress', 'In analysis'],
  ['closed', 'Closed'],
  ['false_positive', 'False positive'],
]

const EMPTY_FORM: CaseFormState = { title: '', description: '', severity: 'medium', status: 'open' }

export function Cases({ tenantId }: { tenantId: string }) {
  const { hasRole } = useAuthStore()
  const [statusFilter, setStatusFilter] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const { data, isLoading, error } = useCases(tenantId, statusFilter)
  const createCase = useCreateCase(tenantId)
  const updateCase = useUpdateCase(tenantId)
  const deleteCase = useDeleteCase(tenantId)

  const [form, setForm] = useState<CaseFormState | null>(null)
  const [editId, setEditId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)

  const canMutate = hasRole('analyst') || hasRole('tenant_admin') || hasRole('super_admin')
  const canDelete = hasRole('tenant_admin') || hasRole('super_admin')

  const selected = data?.items.find((c) => c.id === selectedId) ?? null

  const columns = [
    col.accessor('title', {
      header: 'Title',
      cell: (info) => (
        <button className="link text-left" onClick={() => setSelectedId(info.row.original.id)}>
          {info.getValue()}
        </button>
      ),
    }),
    col.accessor('status', {
      header: 'Status',
      cell: (info) => (
        <span className={`badge ${STATUS_BADGE[info.getValue()] ?? 'badge-neutral'}`}>
          {STATUS_LABEL[info.getValue()] ?? info.getValue()}
        </span>
      ),
    }),
    col.accessor('severity', {
      header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    }),
    col.accessor('sla_status', {
      header: 'SLA',
      cell: (info) => <SlaBadge status={info.getValue()} />,
    }),
    col.accessor('created_at', { header: 'Created' }),
    col.display({
      id: 'actions',
      header: '',
      cell: (info) => (
        <div className="flex gap-2">
          {canMutate && (
            <button
              className="text-xs link"
              onClick={() => {
                const row = info.row.original
                setEditId(row.id)
                setForm({ title: row.title, description: row.description ?? '', severity: row.severity, status: row.status })
              }}
            >
              Edit
            </button>
          )}
          {canDelete && (
            <button
              className="text-xs link-danger"
              onClick={() => setDeleteId(info.row.original.id)}
            >
              Delete
            </button>
          )}
        </div>
      ),
    }),
  ]

  const submitForm = () => {
    if (!form) return
    if (editId) {
      updateCase.mutate({ id: editId, title: form.title, description: form.description, status: form.status, severity: form.severity })
    } else {
      createCase.mutate({ title: form.title, description: form.description, severity: form.severity })
    }
    setForm(null)
    setEditId(null)
  }

  return (
    <div>
      <div className="mb-3 flex items-center justify-end">
        {canMutate && (
          <button
            onClick={() => { setEditId(null); setForm(EMPTY_FORM) }}
            className="btn btn-primary"
          >
            New Case
          </button>
        )}
      </div>

      <div className="mb-3 flex flex-wrap gap-1" role="tablist" aria-label="Filter by status">
        {FILTERS.map(([value, label]) => (
          <button
            key={value || 'all'}
            role="tab"
            aria-selected={statusFilter === value}
            onClick={() => setStatusFilter(value)}
            className={statusFilter === value ? 'btn btn-primary' : 'btn btn-ghost'}
          >
            {label}
          </button>
        ))}
      </div>

      <ErrorMessage error={error as Error | null} />
      <DataTable columns={columns} data={data?.items ?? []} isLoading={isLoading} />

      {selected && (
        <CaseDetail
          key={selected.id}
          tenantId={tenantId}
          item={selected}
          onClose={() => setSelectedId(null)}
        />
      )}

      {form !== null && (
        <div className="modal-backdrop">
          <div className="modal max-w-md">
            <h2 className="mb-4 text-lg font-semibold">{editId ? 'Edit Case' : 'New Case'}</h2>
            <div className="space-y-3">
              <input
                className="field"
                placeholder="Title"
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
              />
              <textarea
                className="field"
                placeholder="Description"
                rows={3}
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
              <select
                className="field"
                value={form.severity}
                onChange={(e) => setForm({ ...form, severity: e.target.value })}
              >
                {['critical', 'high', 'medium', 'low'].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
              {editId && (
                <select
                  className="field"
                  value={form.status}
                  onChange={(e) => setForm({ ...form, status: e.target.value })}
                >
                  {['open', 'in_progress', 'closed', 'false_positive'].map((s) => (
                    <option key={s} value={s}>{STATUS_LABEL[s]}</option>
                  ))}
                </select>
              )}
            </div>
            <div className="mt-4 flex justify-end gap-3">
              <button onClick={() => { setForm(null); setEditId(null) }} className="btn btn-ghost">
                Cancel
              </button>
              <button onClick={submitForm} className="btn btn-primary">
                {editId ? 'Save' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {deleteId && (
        <ConfirmModal
          title="Delete Case"
          message="Are you sure you want to delete this case? This cannot be undone."
          onConfirm={() => { deleteCase.mutate(deleteId); setDeleteId(null) }}
          onCancel={() => setDeleteId(null)}
        />
      )}
    </div>
  )
}
