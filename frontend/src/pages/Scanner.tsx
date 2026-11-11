import { useState } from 'react'
import { useAuthStore } from '@/auth/store'

type Engine = 'tenable' | 'qualys' | 'nessus' | 'nuclei' | 'openvas'
type Tab = 'profiles' | 'runs'

const ENGINES: { id: Engine; label: string; desc: string }[] = [
  { id: 'tenable', label: 'Tenable', desc: 'Nessus-based enterprise scanner' },
  { id: 'qualys', label: 'Qualys VMDR', desc: 'Cloud vulnerability management' },
  { id: 'nessus', label: 'Nessus', desc: 'Vulnerability scanner' },
  { id: 'nuclei', label: 'Nuclei', desc: 'Open-source template-based scanner' },
  { id: 'openvas', label: 'OpenVAS', desc: 'Open Vulnerability Assessment System' },
]

export function Scanner({ tenantId }: { tenantId: string }) {
  const { hasRole } = useAuthStore()
  const canAdmin = hasRole('tenant_admin') || hasRole('super_admin')
  const [tab, setTab] = useState<Tab>('profiles')

  return (
    <div className="space-y-4">
      <div
        className="rounded-lg px-4 py-3 text-sm"
        style={{ background: 'rgba(234,179,8,.08)', border: '1px solid rgba(234,179,8,.2)', color: '#eab308' }}
      >
        Security Scanner — coming in next release. Configure your scan engine credentials to enable automatic vulnerability scanning.
      </div>

      <div className="flex gap-2" role="tablist">
        {(['profiles', 'runs'] as Tab[]).map((t) => (
          <button
            key={t} role="tab" aria-selected={tab === t}
            className={tab === t ? 'btn btn-primary' : 'btn btn-ghost'}
            onClick={() => setTab(t)}
          >
            {t === 'profiles' ? 'Scan Profiles' : 'Scan Runs'}
          </button>
        ))}
      </div>

      {tab === 'profiles' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm muted">No scan profiles configured yet.</p>
            {canAdmin && (
              <button className="btn btn-primary" disabled title="Coming soon">New profile</button>
            )}
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {ENGINES.map((e) => (
              <div
                key={e.id}
                className="rounded-lg p-4"
                style={{ background: 'var(--bg2)', border: '1px solid var(--border)' }}
              >
                <div className="font-semibold text-sm">{e.label}</div>
                <div className="text-xs mt-1" style={{ color: 'var(--text2)' }}>{e.desc}</div>
                <div className="mt-3 flex items-center gap-2">
                  <span
                    className="inline-block rounded-full px-2 py-0.5 text-xs font-medium"
                    style={{ background: 'rgba(100,116,139,.12)', color: 'var(--text3)' }}
                  >
                    not configured
                  </span>
                  {canAdmin && (
                    <button className="text-xs" style={{ color: 'var(--accent)' }} disabled>
                      Configure
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === 'runs' && (
        <p className="text-sm muted">No scan runs yet. Create a scan profile and trigger a run.</p>
      )}
    </div>
  )
}
