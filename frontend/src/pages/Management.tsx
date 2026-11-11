import { useState } from 'react'
import { Link } from 'react-router-dom'
import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ConfirmModal } from '@/components/ConfirmModal'
import { ErrorMessage } from '@/components/ErrorMessage'
import { FormModal } from '@/components/FormModal'
import { useAuthStore } from '@/auth/store'
import {
  useApiKeys,
  useAuditLog,
  useCreateApiKey,
  useCreateTenant,
  useRevokeApiKey,
  useTenants,
  useUpdateTenant,
} from '@/api/hooks/useManagement'
import {
  useDeleteIntegrationKey,
  useIntegrations,
  useSetIntegrationKey,
} from '@/api/hooks/useIntegrations'
import type { ApiKey, ApiKeyCreated, AuditEntry, TenantInfo } from '@/api/types'

type Tab = 'keys' | 'integrations' | 'audit' | 'tenants' | 'roles'

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '—')
const STATUS_BADGE: Record<string, string> = {
  active: 'badge-low',
  expired: 'badge-medium',
  revoked: 'badge-neutral',
}

const ROLES: [string, string][] = [
  ['super_admin', 'All tenants: manages tenants and the shared catalog.'],
  ['tenant_admin', 'Their own tenant: assets, cases, API keys, audit log, scoring settings.'],
  ['analyst', 'Reads everything in the tenant; writes cases, notes, actors, campaigns, observables.'],
  ['viewer', 'Read only: dashboard, exposure, cases, reports.'],
  ['api_user', 'Programmatic access with an API key (header X-API-Key): same tenant, assets and reads.'],
]

/* ---------------------------------------------------------------- API keys */

const keyCol = createColumnHelper<ApiKey>()

function ApiKeysTab({ tenantId }: { tenantId: string }) {
  const { data, isLoading, error } = useApiKeys(tenantId)
  const create = useCreateApiKey(tenantId)
  const revoke = useRevokeApiKey(tenantId)
  const [form, setForm] = useState<{ name: string; days: string } | null>(null)
  const [created, setCreated] = useState<ApiKeyCreated | null>(null)
  const [revokeId, setRevokeId] = useState<string | null>(null)

  const days = form && form.days.trim() ? Number(form.days) : undefined
  const daysOk = days === undefined || (Number.isInteger(days) && days >= 1 && days <= 730)

  const columns = [
    keyCol.accessor('name', { header: 'Name' }),
    keyCol.accessor('prefix', { header: 'Key', cell: (i) => <code className="mono">{i.getValue()}…</code> }),
    keyCol.accessor('status', {
      header: 'Status',
      cell: (i) => <span className={`badge ${STATUS_BADGE[i.getValue()] ?? 'badge-neutral'}`}>{i.getValue()}</span>,
    }),
    keyCol.accessor('expires_at', { header: 'Expires', cell: (i) => fmt(i.getValue()) }),
    keyCol.accessor('last_used_at', { header: 'Last used', cell: (i) => fmt(i.getValue()) }),
    keyCol.display({
      id: 'actions',
      header: '',
      cell: (i) =>
        i.row.original.status === 'revoked' ? null : (
          <button className="text-xs link-danger" onClick={() => setRevokeId(i.row.original.id)}>
            Revoke
          </button>
        ),
    }),
  ]

  return (
    <div>
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="muted text-sm">
          A key gives programmatic access (role api_user) to this tenant only. The full key is shown
          once, when you create it.
        </p>
        <button className="btn btn-primary shrink-0" onClick={() => setForm({ name: '', days: '90' })}>
          New API key
        </button>
      </div>
      <ErrorMessage error={(error ?? revoke.error) as Error | null} />
      <DataTable columns={columns} data={data?.items ?? []} isLoading={isLoading} />

      {form && (
        <FormModal
          title="New API key"
          submitLabel="Create"
          canSubmit={!!form.name.trim() && daysOk}
          isPending={create.isPending}
          error={create.error as Error | null}
          onCancel={() => setForm(null)}
          onSubmit={() =>
            create.mutate(
              { name: form.name.trim(), expires_in_days: days },
              { onSuccess: (k) => { setCreated(k); setForm(null) } },
            )
          }
        >
          <input
            className="field"
            aria-label="Key name"
            placeholder="Name (e.g. SIEM export)"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
          <input
            className="field"
            aria-label="Expires in days"
            placeholder="Expires in days (empty = never)"
            inputMode="numeric"
            value={form.days}
            onChange={(e) => setForm({ ...form, days: e.target.value })}
          />
          {!daysOk && <p className="text-xs" style={{ color: 'var(--critical)' }}>Days: a whole number from 1 to 730.</p>}
        </FormModal>
      )}

      {created && (
        <div className="modal-backdrop">
          <div className="modal max-w-lg" role="dialog" aria-label="New API key created">
            <h2 className="mb-2 text-lg font-semibold">Copy your key now</h2>
            <p className="muted mb-3 text-sm">
              This is the only time the full key is shown. It is not stored: if you lose it, revoke it
              and create a new one.
            </p>
            <code className="mono block break-all rounded-md border p-3 text-sm" style={{ borderColor: 'var(--border)', background: 'var(--bg3)' }}>
              {created.key}
            </code>
            <div className="mt-4 flex justify-end gap-3">
              <button className="btn btn-ghost" onClick={() => navigator.clipboard?.writeText(created.key)}>
                Copy
              </button>
              <button className="btn btn-primary" onClick={() => setCreated(null)}>
                I have saved it
              </button>
            </div>
          </div>
        </div>
      )}

      {revokeId && (
        <ConfirmModal
          title="Revoke API key"
          message="Anything using this key stops working immediately. This cannot be undone."
          onConfirm={() => { revoke.mutate(revokeId); setRevokeId(null) }}
          onCancel={() => setRevokeId(null)}
        />
      )}
    </div>
  )
}

/* ------------------------------------------------------------ integrations */

function IntegrationsTab({ tenantId }: { tenantId: string }) {
  const { data, isLoading, error } = useIntegrations(tenantId)
  const save = useSetIntegrationKey(tenantId)
  const remove = useDeleteIntegrationKey(tenantId)
  const [editing, setEditing] = useState<string | null>(null)
  const [value, setValue] = useState('')
  const [removeProvider, setRemoveProvider] = useState<string | null>(null)

  const close = () => {
    setEditing(null)
    setValue('') // the typed key never stays in the page
    save.reset()
  }

  return (
    <div>
      <p className="muted mb-3 text-sm">
        Keys for outside services, used by the platform on your analysts' behalf. A key is stored
        encrypted and can never be displayed again: you can only replace or remove it.
      </p>
      <ErrorMessage error={(error ?? remove.error) as Error | null} />
      {isLoading && <div className="py-6 text-center muted">Loading…</div>}
      <div className="space-y-3">
        {(data ?? []).map((i) => (
          <div key={i.provider} className="card flex items-center justify-between gap-3">
            <div>
              <div className="font-medium">{i.label}</div>
              <div className="muted text-xs">
                {i.configured ? `Key configured · changed ${fmt(i.updated_at)}` : 'No key configured'}
              </div>
            </div>
            <div className="flex gap-2">
              <button className="btn btn-primary" onClick={() => setEditing(i.provider)}>
                {i.configured ? 'Replace key' : 'Add key'}
              </button>
              {i.configured && (
                <button className="btn btn-ghost" onClick={() => setRemoveProvider(i.provider)}>
                  Remove
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {editing && (
        <FormModal
          title={`${(data ?? []).find((i) => i.provider === editing)?.label ?? ''} API key`}
          submitLabel="Save key"
          canSubmit={value.trim().length > 0}
          isPending={save.isPending}
          error={save.error as Error | null}
          onCancel={close}
          onSubmit={() => save.mutate({ provider: editing, apiKey: value.trim() }, { onSuccess: close })}
        >
          <input
            className="field"
            type="password"
            name="integration-secret"
            aria-label="API key"
            placeholder="Paste the key"
            autoComplete="off"
            spellCheck={false}
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
          <p className="muted text-xs">Once saved it is hidden for good, here and in the API.</p>
        </FormModal>
      )}

      {removeProvider && (
        <ConfirmModal
          title="Remove key"
          message="Enrichment with this service stops working until a new key is added."
          onConfirm={() => { remove.mutate(removeProvider); setRemoveProvider(null) }}
          onCancel={() => setRemoveProvider(null)}
        />
      )}
    </div>
  )
}

/* --------------------------------------------------------------- audit log */

const auditCol = createColumnHelper<AuditEntry>()
const auditColumns = [
  auditCol.accessor('created_at', { header: 'When', cell: (i) => fmt(i.getValue()) }),
  auditCol.accessor('action', { header: 'Action', cell: (i) => <code className="mono text-xs">{i.getValue()}</code> }),
  auditCol.accessor('status_code', { header: 'Status', cell: (i) => i.getValue() ?? '—' }),
  auditCol.accessor('actor_id', {
    header: 'User',
    cell: (i) => (i.getValue() ? <code className="mono text-xs">{i.getValue()!.slice(0, 8)}</code> : '—'),
  }),
  auditCol.accessor('ip', { header: 'IP', cell: (i) => i.getValue() ?? '—' }),
  auditCol.accessor('payload', {
    header: 'Via',
    cell: (i) => (i.getValue()?.via === 'api_key' ? 'API key' : ''),
  }),
]

function AuditTab({ tenantId }: { tenantId: string }) {
  const [page, setPage] = useState(1)
  const [q, setQ] = useState('')
  const { data, isLoading, error } = useAuditLog(tenantId, page, q)
  const pages = data ? Math.max(1, Math.ceil(data.total / data.size)) : 1
  return (
    <div>
      <div className="mb-3 flex items-center gap-3">
        <input
          className="field max-w-xs"
          aria-label="Filter actions"
          placeholder="Filter (e.g. cases, assets, DELETE)"
          value={q}
          onChange={(e) => { setQ(e.target.value); setPage(1) }}
        />
        <span className="muted text-xs">{data ? `${data.total} entries` : ''}</span>
      </div>
      <ErrorMessage error={error as Error | null} />
      <DataTable columns={auditColumns} data={data?.items ?? []} isLoading={isLoading} />
      <div className="mt-3 flex items-center justify-end gap-3 text-sm">
        <button className="btn btn-ghost" disabled={page <= 1} onClick={() => setPage(page - 1)}>
          Previous
        </button>
        <span className="muted">Page {page} of {pages}</span>
        <button className="btn btn-ghost" disabled={page >= pages} onClick={() => setPage(page + 1)}>
          Next
        </button>
      </div>
      <p className="muted mt-3 text-xs">
        Every successful create, change and delete is recorded. Reads are not.
      </p>
    </div>
  )
}

/* ----------------------------------------------------------------- tenants */

const tenantCol = createColumnHelper<TenantInfo>()

function TenantsTab() {
  const { data, isLoading, error } = useTenants(true)
  const create = useCreateTenant()
  const update = useUpdateTenant()
  const [form, setForm] = useState<{ id: string | null; name: string; slug: string; sector: string } | null>(null)
  const mutation = form?.id ? update : create

  const columns = [
    tenantCol.accessor('name', {
      header: 'Name',
      cell: (i) => <Link className="link" to={`/clients?id=${i.row.original.id}`}>{i.getValue()}</Link>,
    }),
    tenantCol.accessor('slug', { header: 'Slug', cell: (i) => <code className="mono">{i.getValue()}</code> }),
    tenantCol.accessor('sector', { header: 'Sector', cell: (i) => i.getValue() ?? '—' }),
    tenantCol.accessor('id', { header: 'Tenant ID', cell: (i) => <code className="mono text-xs">{i.getValue()}</code> }),
    tenantCol.display({
      id: 'actions',
      header: '',
      cell: (i) => (
        <button
          className="text-xs link"
          onClick={() => {
            const t = i.row.original
            setForm({ id: t.id, name: t.name, slug: t.slug, sector: t.sector ?? '' })
          }}
        >
          Edit
        </button>
      ),
    }),
  ]

  const submit = () => {
    if (!form) return
    const sector = form.sector.trim()
    const done = { onSuccess: () => setForm(null) }
    if (form.id) update.mutate({ id: form.id, name: form.name.trim(), sector: sector || null }, done)
    else create.mutate({ name: form.name.trim(), slug: form.slug.trim(), sector: sector || undefined }, done)
  }

  return (
    <div>
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="muted text-sm">
          A new tenant is only the company record. To let its people sign in, create their users in
          Keycloak with the tenant_id attribute set to the Tenant ID below.
        </p>
        <button className="btn btn-primary shrink-0" onClick={() => setForm({ id: null, name: '', slug: '', sector: '' })}>
          New tenant
        </button>
      </div>
      <ErrorMessage error={error as Error | null} />
      <DataTable columns={columns} data={data?.items ?? []} isLoading={isLoading} />
      {form && (
        <FormModal
          title={form.id ? 'Edit tenant' : 'New tenant'}
          submitLabel={form.id ? 'Save' : 'Create'}
          canSubmit={!!form.name.trim() && (!!form.id || form.slug.trim().length >= 2)}
          isPending={mutation.isPending}
          error={mutation.error as Error | null}
          onCancel={() => setForm(null)}
          onSubmit={submit}
        >
          <input className="field" aria-label="Tenant name" placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input
            className="field"
            aria-label="Tenant slug"
            placeholder="Slug (e.g. acme-bank, cannot change later)"
            value={form.slug}
            disabled={!!form.id}
            onChange={(e) => setForm({ ...form, slug: e.target.value })}
          />
          <input className="field" aria-label="Sector" placeholder="Sector (optional)" value={form.sector} onChange={(e) => setForm({ ...form, sector: e.target.value })} />
        </FormModal>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------- roles */

function RolesTab() {
  return (
    <div>
      <p className="muted mb-3 text-sm">
        Users and their roles are managed in Keycloak (realm <code className="mono">sentinel</code>,
        Users → Role mapping). These are the roles the platform understands.
      </p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>Role</th><th>What it can do</th></tr>
          </thead>
          <tbody>
            {ROLES.map(([role, text]) => (
              <tr key={role}>
                <td><code className="mono">{role}</code></td>
                <td>{text}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* -------------------------------------------------------------------- page */

export function Management({ tenantId }: { tenantId: string }) {
  const { hasRole } = useAuthStore()
  const isSuper = hasRole('super_admin')
  const isAdmin = isSuper || hasRole('tenant_admin')
  const [tab, setTab] = useState<Tab>('keys')

  if (!isAdmin) {
    return <p className="muted">Management is available to tenant administrators only.</p>
  }

  const tabs: [Tab, string][] = [
    ['keys', 'API keys'],
    ['integrations', 'Integrations'],
    ['audit', 'Audit log'],
    ...(isSuper ? ([['tenants', 'Tenants']] as [Tab, string][]) : []),
    ['roles', 'Roles'],
  ]

  return (
    <div>
      <div className="mb-4 flex gap-1 border-b" style={{ borderColor: 'var(--border)' }} role="tablist">
        {tabs.map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
            className={`px-3 py-1.5 text-[0.82rem] ${tab === id ? 'font-medium' : 'muted'}`}
            style={tab === id ? { color: 'var(--accent)', borderBottom: '2px solid var(--accent)' } : undefined}
          >
            {label}
          </button>
        ))}
      </div>
      {tab === 'keys' && <ApiKeysTab tenantId={tenantId} />}
      {tab === 'integrations' && <IntegrationsTab tenantId={tenantId} />}
      {tab === 'audit' && <AuditTab tenantId={tenantId} />}
      {tab === 'tenants' && isSuper && <TenantsTab />}
      {tab === 'roles' && <RolesTab />}
    </div>
  )
}
