import { useState } from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ConfirmModal } from '@/components/ConfirmModal'
import { ErrorMessage } from '@/components/ErrorMessage'
import { FormModal } from '@/components/FormModal'
import { useAuthStore } from '@/auth/store'
import {
  useCampaigns,
  useCreateCampaign,
  useUpdateCampaign,
  useDeleteCampaign,
} from '@/api/hooks/useCampaigns'
import { useActors } from '@/api/hooks/useActors'
import type { Campaign } from '@/api/types'

const col = createColumnHelper<Campaign>()

interface FormState {
  name: string
  threat_actor_id: string // '' = none
  description: string
}
const EMPTY: FormState = { name: '', threat_actor_id: '', description: '' }

export function Campaigns({ tenantId }: { tenantId: string }) {
  const { hasRole } = useAuthStore()
  const { data, isLoading, error } = useCampaigns()
  const actors = useActors()
  const create = useCreateCampaign(tenantId)
  const update = useUpdateCampaign(tenantId)
  const remove = useDeleteCampaign(tenantId)
  const [form, setForm] = useState<FormState | null>(null)
  const [editId, setEditId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)

  const canWrite = hasRole('analyst') || hasRole('tenant_admin') || hasRole('super_admin')
  const mutation = editId ? update : create
  const actorName = new Map((actors.data?.items ?? []).map((a) => [a.id, a.name]))

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
      threat_actor_id: form.threat_actor_id || null,
      description: form.description.trim() || null,
    }
    if (editId) update.mutate({ id: editId, ...body }, { onSuccess: close })
    else create.mutate(body, { onSuccess: close })
  }

  const columns = [
    col.accessor('name', { header: 'Name' }),
    col.accessor('threat_actor_id', {
      header: 'Threat Actor',
      cell: ({ getValue }) => {
        const id = getValue()
        return id ? (actorName.get(id) ?? id) : '—'
      },
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
              row.original.tenant_id === tenantId ? (
                <div className="flex gap-2">
                  <button
                    className="text-xs link"
                    onClick={() => {
                      setEditId(row.original.id)
                      setForm({
                        name: row.original.name,
                        threat_actor_id: row.original.threat_actor_id ?? '',
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
            New campaign
          </button>
        </div>
      )}
      <ErrorMessage error={(error ?? remove.error) as Error | null} />
      <DataTable columns={columns} data={data?.items ?? []} isLoading={isLoading} />

      {form && (
        <FormModal
          title={editId ? 'Edit campaign' : 'New campaign'}
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
          <select
            className="field"
            aria-label="Threat actor"
            value={form.threat_actor_id}
            onChange={(e) => setForm({ ...form, threat_actor_id: e.target.value })}
          >
            <option value="">No threat actor</option>
            {(actors.data?.items ?? []).map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
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
          title="Delete campaign"
          message="This cannot be undone."
          onConfirm={() => { remove.mutate(deleteId); setDeleteId(null) }}
          onCancel={() => setDeleteId(null)}
        />
      )}
    </div>
  )
}
