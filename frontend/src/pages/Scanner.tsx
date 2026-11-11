import { useState } from 'react'
import { useAuthStore } from '@/auth/store'
import { useForecast } from '@/api/hooks/useForecast'
import { useSimilarIocs } from '@/api/hooks/useSimilarIocs'

type Engine = 'tenable' | 'qualys' | 'nessus' | 'nuclei' | 'openvas'
type Tab = 'profiles' | 'runs' | 'ai'

const ENGINES: { id: Engine; label: string; desc: string }[] = [
  { id: 'tenable', label: 'Tenable', desc: 'Nessus-based enterprise scanner' },
  { id: 'qualys', label: 'Qualys VMDR', desc: 'Cloud vulnerability management' },
  { id: 'nessus', label: 'Nessus', desc: 'Vulnerability scanner' },
  { id: 'nuclei', label: 'Nuclei', desc: 'Open-source template-based scanner' },
  { id: 'openvas', label: 'OpenVAS', desc: 'Open Vulnerability Assessment System' },
]

function AiInsights({ tenantId }: { tenantId: string }) {
  const [iocQuery, setIocQuery] = useState('')
  const [submitted, setSubmitted] = useState('')
  const forecast = useForecast(tenantId, 7)
  const similar = useSimilarIocs(submitted, 10)

  return (
    <div className="space-y-6">
      <div>
        <h3 className="font-semibold mb-3 text-sm">Risk Score Forecast (next 7 days)</h3>
        {forecast.isLoading && <p className="text-sm muted">Loading…</p>}
        {forecast.data?.message && <p className="text-sm muted">{forecast.data.message}</p>}
        {forecast.data?.forecast && forecast.data.forecast.length > 0 && (
          <div className="flex items-end gap-1 h-16">
            {forecast.data.forecast.map((v, i) => (
              <div
                key={i}
                className="flex-1 rounded-t"
                style={{
                  height: `${Math.round(v * 100)}%`,
                  minHeight: 2,
                  background: v > 0.7 ? '#ef4444' : v > 0.4 ? '#f59e0b' : '#22c55e',
                }}
                title={`Day ${i + 1}: ${(v * 100).toFixed(1)}%`}
              />
            ))}
          </div>
        )}
      </div>

      <div>
        <h3 className="font-semibold mb-3 text-sm">Similar IoC Search</h3>
        <div className="flex gap-2">
          <input
            className="input flex-1"
            placeholder="Enter IP, domain or hash…"
            value={iocQuery}
            onChange={(e) => setIocQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && setSubmitted(iocQuery)}
          />
          <button className="btn btn-primary" onClick={() => setSubmitted(iocQuery)}>
            Search
          </button>
        </div>
        {similar.isLoading && <p className="text-sm muted mt-2">Searching…</p>}
        {similar.data?.message && <p className="text-sm muted mt-2">{similar.data.message}</p>}
        {similar.data?.results && similar.data.results.length > 0 && (
          <ul className="mt-3 space-y-1">
            {similar.data.results.map((r) => (
              <li key={r.value} className="flex justify-between text-sm rounded px-3 py-1.5" style={{ background: 'var(--bg2)' }}>
                <span className="font-mono">{r.value}</span>
                <span className="muted">{(r.score * 100).toFixed(1)}%</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

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
        {([['profiles', 'Scan Profiles'], ['runs', 'Scan Runs'], ['ai', 'AI Insights']] as [Tab, string][]).map(([t, label]) => (
          <button
            key={t} role="tab" aria-selected={tab === t}
            className={tab === t ? 'btn btn-primary' : 'btn btn-ghost'}
            onClick={() => setTab(t)}
          >
            {label}
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

      {tab === 'ai' && <AiInsights tenantId={tenantId} />}
    </div>
  )
}
