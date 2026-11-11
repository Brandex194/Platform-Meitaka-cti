import { useState } from 'react'
import { useAuthStore } from '@/auth/store'

type Tab = 'engagements' | 'scope' | 'evidence'

const GOVERNANCE_RULES = [
  'Written authorization required before any engagement is activated.',
  'Scope must be declared and stored before execution begins.',
  'Kill-switch available to tenant_admin and super_admin at any time.',
  'All activity is recorded in the immutable audit log.',
  'No destructive actions outside declared scope are permitted.',
]

export function RedTeam({ tenantId }: { tenantId: string }) {
  const { hasRole } = useAuthStore()
  const canAdmin = hasRole('tenant_admin') || hasRole('super_admin')
  const [tab, setTab] = useState<Tab>('engagements')

  return (
    <div className="space-y-4">
      {/* Governance notice */}
      <div
        className="rounded-lg px-4 py-3"
        style={{ background: 'rgba(244,63,94,.06)', border: '1px solid rgba(244,63,94,.2)' }}
      >
        <div className="text-sm font-semibold mb-2" style={{ color: '#f43f5e' }}>
          Red Team Governance — Mandatory Requirements
        </div>
        <ul className="space-y-1">
          {GOVERNANCE_RULES.map((r) => (
            <li key={r} className="text-xs flex gap-2" style={{ color: 'var(--text2)' }}>
              <span style={{ color: '#f43f5e' }}>•</span>
              {r}
            </li>
          ))}
        </ul>
      </div>

      <div
        className="rounded-lg px-4 py-3 text-sm"
        style={{ background: 'rgba(234,179,8,.08)', border: '1px solid rgba(234,179,8,.2)', color: '#eab308' }}
      >
        Red Team Ops — coming in next release. Execution engine and tool integrations are under development.
      </div>

      <div className="flex gap-2" role="tablist">
        {(['engagements', 'scope', 'evidence'] as Tab[]).map((t) => (
          <button
            key={t} role="tab" aria-selected={tab === t}
            className={tab === t ? 'btn btn-primary' : 'btn btn-ghost'}
            onClick={() => setTab(t)}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {tab === 'engagements' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm muted">No engagements yet.</p>
            {canAdmin && (
              <button className="btn btn-primary" disabled title="Coming soon">New engagement</button>
            )}
          </div>
          <p className="text-xs muted">
            Each engagement requires: a name, written authorization (name/role of approver), and a declared scope before it can be activated.
          </p>
        </div>
      )}

      {tab === 'scope' && (
        <p className="text-sm muted">Scope declarations will appear here once an engagement is created.</p>
      )}

      {tab === 'evidence' && (
        <p className="text-sm muted">Evidence artifacts (screenshots, logs, findings) will be stored here per engagement.</p>
      )}
    </div>
  )
}
