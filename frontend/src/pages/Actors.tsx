import { useState } from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ConfirmModal } from '@/components/ConfirmModal'
import { ErrorMessage } from '@/components/ErrorMessage'
import { FormModal } from '@/components/FormModal'
import { useAuthStore } from '@/auth/store'
import {
  useActors,
  useCreateActor,
  useUpdateActor,
  useDeleteActor,
} from '@/api/hooks/useActors'
import type { ThreatActor } from '@/api/types'

const col = createColumnHelper<ThreatActor>()

interface FormState {
  name: string
  aliases: string // comma separated while typing
  description: string
}
const EMPTY: FormState = { name: '', aliases: '', description: '' }

const splitAliases = (text: string) =>
  text
    .split(',')
    .map((a) => a.trim())
    .filter(Boolean)

export function Actors({ tenantId }: { tenantId: string }) {
  const { hasRole } = useAuthStore()
  const { data, isLoading, error } = useActors()
  const create = useCreateActor(tenantId)
  const update = useUpdateActor(tenantId)
  const remove = useDeleteActor(tenantId)
  const [form, setForm] = useState<FormState | null>(null)
  const [editId, setEditId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)

  const canWrite = hasRole('analyst') || hasRole('tenant_admin') || hasRole('super_admin')
  const mutation = editId ? update : create

  const close = () => {
    setForm(null)
    setEditId(null)
    create.reset()
    update.reset()
  }

  const submit = () => {
    if (!form) return
    const body = {
      name: form.name.trim(),
      aliases: splitAliases(form.aliases),
      description: form.description.trim() || null,
    }
    if (editId) update.mutate({ id: editId, ...body }, { onSuccess: close })
    else create.mutate(body, { onSuccess: close })
  }

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
    col.accessor('tenant_id', {
      header: 'Source',
      cell: ({ getValue }) =>
        getValue() ? <span className="badge badge-info">yours</span> : <span className="badge badge-neutral">shared</span>,
    }),
    col.accessor('created_at', { header: 'Added' }),
    ...(canWrite
      ? [
          col.display({
            id: 'actions',
            header: 'Actions',
            cell: ({ row }) =>
              // Shared catalog entries come from the feeds: only the tenant's own can be changed.
              row.original.tenant_id === tenantId ? (
                <div className="flex gap-2">
                  <button
                    className="text-xs link"
                    onClick={() => {
                      setEditId(row.original.id)
                      setForm({
                        name: row.original.name,
                        aliases: (row.original.aliases ?? []).join(', '),
                        description: row.original.description ?? '',
                      })
                    }}
                  >
                    Edit
                  </button>
                  <button className="text-xs link-danger" onClick={() => setDeleteId(row.original.id)}>
                    Delete
                  </button>
                </div>
              ) : null,
          }),
        ]
      : []),
  ]

  return (
    <div>
      {canWrite && (
        <div className="mb-3 flex items-center justify-end">
          <button className="btn btn-primary" onClick={() => { setEditId(null); setForm(EMPTY) }}>
            New actor
          </button>
        </div>
      )}
      <ErrorMessage error={(error ?? remove.error) as Error | null} />
      <DataTable columns={columns} data={data?.items ?? []} isLoading={isLoading} />

      {form && (
        <FormModal
          title={editId ? 'Edit threat actor' : 'New threat actor'}
          submitLabel={editId ? 'Save' : 'Create'}
          onSubmit={submit}
          onCancel={close}
          canSubmit={form.name.trim().length > 0}
          isPending={mutation.isPending}
          error={mutation.error as Error | null}
        >
          <input
            className="field"
            placeholder="Name"
            aria-label="Name"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
          <input
            className="field"
            placeholder="Aliases, separated by commas"
            aria-label="Aliases"
            value={form.aliases}
            onChange={(e) => setForm({ ...form, aliases: e.target.value })}
          />
          <textarea
            className="field"
            placeholder="Description"
            aria-label="Description"
            rows={3}
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
        </FormModal>
      )}

      {deleteId && (
        <ConfirmModal
          title="Delete threat actor"
          message="Its campaigns stay, without the link to this actor."
          onConfirm={() => { remove.mutate(deleteId); setDeleteId(null) }}
          onCancel={() => setDeleteId(null)}
        />
      )}
    </div>
  )
}
