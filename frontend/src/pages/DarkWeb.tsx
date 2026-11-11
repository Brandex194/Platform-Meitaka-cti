import { useState } from 'react'
import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ErrorMessage } from '@/components/ErrorMessage'
import { FormModal } from '@/components/FormModal'
import { ConfirmModal } from '@/components/ConfirmModal'
import { SeverityBadge } from '@/components/SeverityBadge'
import { useAuthStore } from '@/auth/store'
import { useObservations } from '@/api/hooks/useObservations'
import {
  useLeaks, useCreateFinding, useSetFindingStatus, useDeleteFinding, useCreateLeak, useDeleteLeak,
  type DarkWebLeak,
} from '@/api/hooks/useDarkWeb'
import type { Observation } from '@/api/types'

const SEVERITIES = ['low', 'medium', 'high', 'critical']
const field = (o: Observation, k: string) => ((o.payload as Record<string, unknown> | null)?.[k] as string | undefined)

type Tab = 'findings' | 'leaks'
type Dialog = null | 'finding' | 'leak'

export function DarkWeb({ tenantId }: { tenantId: string }) {
  const { hasRole } = useAuthStore()
  const canWrite = hasRole('analyst') || hasRole('tenant_admin') || hasRole('super_admin')
  const [tab, setTab] = useState<Tab>('findings')
  const [dialog, setDialog] = useState<Dialog>(null)
  const [confirm, setConfirm] = useState<{ kind: Tab; id: string } | null>(null)
  const [finding, setFinding] = useState({ source: '', context: '', severity: 'medium' })
  const [leak, setLeak] = useState({ email: '', breach_name: '', pwn_count: '' })

  const findings = useObservations(tenantId, 'darkweb')
  const leaks = useLeaks(tenantId)
  const createFinding = useCreateFinding(tenantId)
  const setStatus = useSetFindingStatus(tenantId)
  const delFinding = useDeleteFinding(tenantId)
  const createLeak = useCreateLeak(tenantId)
  const delLeak = useDeleteLeak(tenantId)

  const fc = createColumnHelper<Observation>()
  const findingColumns = [
    fc.display({ id: 'severity', header: 'Severity', cell: (i) => <SeverityBadge severity={field(i.row.original, 'severity') ?? 'medium'} /> }),
    fc.display({ id: 'source', header: 'Source', cell: (i) => field(i.row.original, 'source') ?? '—' }),
    fc.display({ id: 'context', header: 'Context', cell: (i) => field(i.row.original, 'context') ?? '—' }),
    fc.display({
      id: 'status',
      header: 'Status',
      cell: (i) => {
        const o = i.row.original
        const s = field(o, 'status') ?? 'new'
        return canWrite ? (
          <select
            className="field-inline"
            aria-label={`Status of ${field(o, 'source') ?? 'finding'}`}
            value={s}
            onChange={(e) => setStatus.mutate({ id: o.id, status: e.target.value })}
          >
            <option value="new">new</option>
            <option value="reviewed">reviewed</option>
            <option value="dismissed">dismissed</option>
          </select>
        ) : s
      },
    }),
    fc.accessor('created_at', { header: 'Recorded' }),
    ...(canWrite
      ? [fc.display({
          id: 'actions', header: '',
          cell: (i) => <button className="text-xs link-danger" onClick={() => setConfirm({ kind: 'findings', id: i.row.original.id })}>Delete</button>,
        })]
      : []),
  ]

  const lc = createColumnHelper<DarkWebLeak>()
  const leakColumns = [
    lc.accessor('breach_name', { header: 'Breach' }),
    lc.accessor('email_hash', { header: 'Email (SHA-256)', cell: (c) => <code>{c.getValue().slice(0, 12)}…</code> }),
    lc.accessor('pwn_count', { header: 'Accounts in breach', cell: (c) => c.getValue() ?? '—' }),
    lc.accessor('created_at', { header: 'Recorded' }),
    ...(canWrite
      ? [lc.display({
          id: 'actions', header: '',
          cell: (i) => <button className="text-xs link-danger" onClick={() => setConfirm({ kind: 'leaks', id: i.row.original.id })}>Delete</button>,
        })]
      : []),
  ]

  const submitFinding = () =>
    createFinding.mutate(finding, {
      onSuccess: () => { setDialog(null); setFinding({ source: '', context: '', severity: 'medium' }) },
    })
  const submitLeak = () =>
    createLeak.mutate(
      {
        email: leak.email,
        breach_name: leak.breach_name,
        ...(leak.pwn_count ? { pwn_count: Number(leak.pwn_count) } : {}),
      },
      { onSuccess: () => { setDialog(null); setLeak({ email: '', breach_name: '', pwn_count: '' }) } },
    )

  const doDelete = () => {
    if (!confirm) return
    ;(confirm.kind === 'findings' ? delFinding : delLeak).mutate(confirm.id)
    setConfirm(null)
  }

  return (
    <div className="space-y-3">
      <p className="text-sm muted">
        Meitaka does not crawl the dark web. You record here what an analyst or an external service found.
        Leaked emails are stored only as a SHA-256 hash and are matched against your identities
        (rule <code>leak_identity</code>).
      </p>
      <div className="flex items-center justify-between gap-3">
        <div className="flex gap-2" role="tablist">
          {(['findings', 'leaks'] as Tab[]).map((t) => (
            <button
              key={t}
              role="tab"
              aria-selected={tab === t}
              className={tab === t ? 'btn btn-primary' : 'btn btn-ghost'}
              onClick={() => setTab(t)}
            >
              {t === 'findings' ? 'Findings' : 'Leaks'}
            </button>
          ))}
        </div>
        {canWrite && (
          <button className="btn btn-primary" onClick={() => setDialog(tab === 'findings' ? 'finding' : 'leak')}>
            {tab === 'findings' ? 'Add finding' : 'Add leak'}
          </button>
        )}
      </div>

      {tab === 'findings' ? (
        <>
          <ErrorMessage error={findings.error as Error | null} />
          <DataTable columns={findingColumns} data={findings.data?.items ?? []} isLoading={findings.isLoading} />
        </>
      ) : (
        <>
          <ErrorMessage error={leaks.error as Error | null} />
          <DataTable columns={leakColumns} data={leaks.data?.items ?? []} isLoading={leaks.isLoading} />
        </>
      )}

      {dialog === 'finding' && (
        <FormModal
          title="Add dark web finding" submitLabel="Add" onSubmit={submitFinding} onCancel={() => setDialog(null)}
          canSubmit={!!finding.source.trim() && !!finding.context.trim()}
          isPending={createFinding.isPending} error={createFinding.error as Error | null}
        >
          <label className="block text-sm">Source
            <input className="field w-full" value={finding.source} maxLength={255} placeholder="forum, marketplace, paste site…"
              onChange={(e) => setFinding({ ...finding, source: e.target.value })} />
          </label>
          <label className="block text-sm">What was found
            <textarea className="field w-full" rows={3} value={finding.context} maxLength={2000}
              onChange={(e) => setFinding({ ...finding, context: e.target.value })} />
          </label>
          <label className="block text-sm">Severity
            <select className="field w-full" value={finding.severity} onChange={(e) => setFinding({ ...finding, severity: e.target.value })}>
              {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
            </select>
          </label>
        </FormModal>
      )}
      {dialog === 'leak' && (
        <FormModal
          title="Add leaked email" submitLabel="Add" onSubmit={submitLeak} onCancel={() => setDialog(null)}
          canSubmit={/^[^@\s]+@[^@\s]+$/.test(leak.email.trim()) && !!leak.breach_name.trim()}
          isPending={createLeak.isPending} error={createLeak.error as Error | null}
        >
          <label className="block text-sm">Email
            <input className="field w-full" type="email" value={leak.email} autoComplete="off"
              onChange={(e) => setLeak({ ...leak, email: e.target.value })} />
          </label>
          <p className="muted text-xs">Only its SHA-256 hash is saved; the address itself is never stored.</p>
          <label className="block text-sm">Breach name
            <input className="field w-full" value={leak.breach_name} maxLength={255}
              onChange={(e) => setLeak({ ...leak, breach_name: e.target.value })} />
          </label>
          <label className="block text-sm">Accounts in the breach (optional)
            <input className="field w-full" type="number" min={0} value={leak.pwn_count}
              onChange={(e) => setLeak({ ...leak, pwn_count: e.target.value })} />
          </label>
        </FormModal>
      )}
      {confirm && (
        <ConfirmModal
          title={confirm.kind === 'findings' ? 'Delete finding' : 'Delete leak'}
          message="This cannot be undone."
          onConfirm={doDelete} onCancel={() => setConfirm(null)}
        />
      )}
    </div>
  )
}
