import { useState } from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { SeverityBadge } from '@/components/SeverityBadge'
import { ConfirmModal } from '@/components/ConfirmModal'
import { ErrorMessage } from '@/components/ErrorMessage'
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

const EMPTY_FORM: CaseFormState = { title: '', description: '', severity: 'medium', status: 'open' }

export function Cases({ tenantId }: { tenantId: string }) {
  const { hasRole } = useAuthStore()
  const { data, isLoading, error } = useCases(tenantId)
  const createCase = useCreateCase(tenantId)
  const updateCase = useUpdateCase(tenantId)
  const deleteCase = useDeleteCase(tenantId)

  const [form, setForm] = useState<CaseFormState | null>(null)
  const [editId, setEditId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)

  const canMutate = hasRole('analyst') || hasRole('tenant_admin') || hasRole('super_admin')
  const canDelete = hasRole('tenant_admin') || hasRole('super_admin')

  const columns = [
    col.accessor('title', { header: 'Title' }),
    col.accessor('status', {
      header: 'Status',
      cell: (info) => (
        <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${info.getValue() === 'open' ? 'bg-orange-100 text-orange-700' : 'bg-green-100 text-green-700'}`}>
          {info.getValue()}
        </span>
      ),
    }),
    col.accessor('severity', {
      header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    }),
    col.accessor('created_at', { header: 'Created' }),
    col.display({
      id: 'actions',
      header: '',
      cell: (info) => (
        <div className="flex gap-2">
          {canMutate && (
            <button
              className="text-xs text-blue-600 hover:underline"
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
              className="text-xs text-red-600 hover:underline"
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
      updateCase.mutate({ id: editId, title: form.title, status: form.status, severity: form.severity })
    } else {
      createCase.mutate({ title: form.title, description: form.description, severity: form.severity })
    }
    setForm(null)
    setEditId(null)
  }

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Cases</h1>
        {canMutate && (
          <button
            onClick={() => { setEditId(null); setForm(EMPTY_FORM) }}
            className="rounded bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
          >
            New Case
          </button>
        )}
      </div>

      <ErrorMessage error={error as Error | null} />
      <DataTable columns={columns} data={data?.items ?? []} isLoading={isLoading} />

      {form !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="w-full max-w-md rounded-lg bg-white p-6 shadow-xl">
            <h2 className="mb-4 text-lg font-semibold">{editId ? 'Edit Case' : 'New Case'}</h2>
            <div className="space-y-3">
              <input
                className="w-full rounded border px-3 py-2 text-sm"
                placeholder="Title"
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
              />
              <textarea
                className="w-full rounded border px-3 py-2 text-sm"
                placeholder="Description"
                rows={3}
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
              <select
                className="w-full rounded border px-3 py-2 text-sm"
                value={form.severity}
                onChange={(e) => setForm({ ...form, severity: e.target.value })}
              >
                {['critical', 'high', 'medium', 'low'].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
              {editId && (
                <select
                  className="w-full rounded border px-3 py-2 text-sm"
                  value={form.status}
                  onChange={(e) => setForm({ ...form, status: e.target.value })}
                >
                  {['open', 'in_progress', 'closed'].map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              )}
            </div>
            <div className="mt-4 flex justify-end gap-3">
              <button onClick={() => { setForm(null); setEditId(null) }} className="rounded px-4 py-2 text-sm text-gray-600 hover:bg-gray-100">
                Cancel
              </button>
              <button onClick={submitForm} className="rounded bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700">
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
