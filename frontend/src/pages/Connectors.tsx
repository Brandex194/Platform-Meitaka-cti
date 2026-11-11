import { useState } from 'react'
import { ErrorMessage } from '@/components/ErrorMessage'
import { FormModal } from '@/components/FormModal'
import { ConfirmModal } from '@/components/ConfirmModal'
import { useAuthStore } from '@/auth/store'
import { useConnectors, useSetConnector, useDeleteConnector } from '@/api/hooks/useConnectors'
import type { ConnectorStatus } from '@/api/types'

const CONNECTOR_DOCS: Record<string, string> = {
  misp: 'MISP threat sharing platform — bidirectional IoC sync',
  opencti: 'OpenCTI threat intelligence platform',
  thehive: 'TheHive case management + Cortex analyzers',
  taxii: 'TAXII 2.1 server — STIX object distribution',
  splunk: 'Splunk SIEM — push correlation events and alerts',
  qradar: 'IBM QRadar SIEM — outbound event push',
  sentinel: 'Microsoft Sentinel — Workspace data connector',
}

export function Connectors({ tenantId }: { tenantId: string }) {
  const { hasRole } = useAuthStore()
  const canAdmin = hasRole('tenant_admin') || hasRole('super_admin')

  const { data, isLoading, error } = useConnectors(tenantId)
  const setConnector = useSetConnector(tenantId)
  const deleteConnector = useDeleteConnector(tenantId)

  const [configuring, setConfiguring] = useState<ConnectorStatus | null>(null)
  const [form, setForm] = useState({ url: '', apiKey: '' })
  const [deleting, setDeleting] = useState<ConnectorStatus | null>(null)

  const submit = () => {
    if (!configuring) return
    setConnector.mutate(
      { provider: configuring.provider, url: form.url, apiKey: form.apiKey },
      { onSuccess: () => { setConfiguring(null); setForm({ url: '', apiKey: '' }) } },
    )
  }

  const confirmDelete = () => {
    if (!deleting) return
    deleteConnector.mutate(deleting.provider, { onSuccess: () => setDeleting(null) })
  }

  if (error) return <ErrorMessage error={error as Error} />

  const connectors = data ?? []

  return (
    <div className="space-y-4">
      <p className="text-sm muted">
        External CTI platform connectors. Credentials are stored encrypted in the vault and never returned by the API.
      </p>

      {isLoading ? (
        <div className="muted text-sm">Loading connectors…</div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {connectors.map((c) => (
            <div
              key={c.provider}
              className="rounded-lg p-4"
              style={{ background: 'var(--bg2)', border: `1px solid ${c.configured ? 'rgba(34,197,94,.2)' : 'var(--border)'}` }}
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="font-semibold text-sm">{c.label}</div>
                  <div className="text-xs mt-0.5" style={{ color: 'var(--text2)' }}>
                    {CONNECTOR_DOCS[c.provider] ?? c.provider}
                  </div>
                </div>
                <span
                  className="shrink-0 rounded-full px-2 py-0.5 text-xs font-medium"
                  style={c.configured
                    ? { background: 'rgba(34,197,94,.1)', color: '#22c55e' }
                    : { background: 'rgba(100,116,139,.1)', color: 'var(--text3)' }}
                >
                  {c.configured ? 'connected' : 'not configured'}
                </span>
              </div>
              {c.configured && c.updated_at && (
                <div className="mt-2 text-xs" style={{ color: 'var(--text3)' }}>
                  Last updated: {new Date(c.updated_at).toLocaleDateString()}
                </div>
              )}
              {canAdmin && (
                <div className="mt-3 flex gap-2">
                  <button
                    className="text-xs"
                    style={{ color: 'var(--accent)' }}
                    onClick={() => { setConfiguring(c); setForm({ url: '', apiKey: '' }) }}
                  >
                    {c.configured ? 'Update' : 'Configure'}
                  </button>
                  {c.configured && (
                    <button
                      className="text-xs link-danger"
                      onClick={() => setDeleting(c)}
                    >
                      Remove
                    </button>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {configuring && (
        <FormModal
          title={`Configure ${configuring.label}`}
          submitLabel="Save"
          onSubmit={submit}
          onCancel={() => setConfiguring(null)}
          canSubmit={!!form.url.trim() && !!form.apiKey.trim()}
          isPending={setConnector.isPending}
          error={setConnector.error as Error | null}
        >
          <label className="block text-sm">URL
            <input
              className="field w-full" type="url" value={form.url}
              placeholder="https://your-instance.example.com"
              onChange={(e) => setForm({ ...form, url: e.target.value })}
            />
          </label>
          <label className="block text-sm">API Key
            <input
              className="field w-full" type="password" value={form.apiKey}
              autoComplete="new-password"
              onChange={(e) => setForm({ ...form, apiKey: e.target.value })}
            />
          </label>
          <p className="text-xs muted">The key is encrypted before storage and will never be shown again.</p>
        </FormModal>
      )}

      {deleting && (
        <ConfirmModal
          title={`Remove ${deleting.label}`}
          message="This will delete the stored credentials. The connector will stop syncing."
          onConfirm={confirmDelete}
          onCancel={() => setDeleting(null)}
        />
      )}
    </div>
  )
}
