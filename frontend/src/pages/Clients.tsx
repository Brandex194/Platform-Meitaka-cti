import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'
import { ErrorMessage } from '@/components/ErrorMessage'
import { RiskGauge } from '@/components/RiskGauge'
import { RiskLevelBadge } from '@/components/RiskLevelBadge'
import { useAuthStore } from '@/auth/store'
import { useTenants } from '@/api/hooks/useManagement'
import { useQuickReport } from '@/api/hooks/useReports'
import { Assets } from './Assets'
import { Scores } from './Scores'
import { Exposure } from './Exposure'
import { Cases } from './Cases'
import { Actors } from './Actors'
import { Campaigns } from './Campaigns'
import { Observables } from './Observables'
import { DarkWeb } from './DarkWeb'
import { AttackHeatmap } from './AttackHeatmap'
import { Reports } from './Reports'
import type { TenantInfo } from '@/api/types'

type Tab = 'overview' | 'assets' | 'scores' | 'exposure' | 'cases' | 'actors' | 'campaigns' | 'observables' | 'darkweb' | 'attack'

const TABS: [Tab, string][] = [
  ['overview', 'Overview'],
  ['assets', 'Assets'],
  ['scores', 'Scores'],
  ['exposure', 'Exposure'],
  ['cases', 'Cases'],
  ['actors', 'Threat Actors'],
  ['campaigns', 'Campaigns'],
  ['observables', 'Observables'],
  ['darkweb', 'Dark Web'],
  ['attack', 'ATT&CK'],
]

const col = createColumnHelper<TenantInfo>()

// Each row fetches its own Quick Report: a handful of clients, so the per-row call is cheap and
// keeps this list honest (the gauge shows the real highest-risk asset, not a guess).
function RiskCell({ tenantId }: { tenantId: string }) {
  const { data, isLoading } = useQuickReport(tenantId)
  if (isLoading) return <span className="muted text-xs">…</span>
  const top = data?.top_assets[0]
  if (!top) return <span className="muted text-xs">No data</span>
  return (
    <span className="flex items-center gap-2">
      <RiskGauge value={top.value} level={top.level} size={28} />
      <RiskLevelBadge level={top.level} />
    </span>
  )
}

export function Clients() {
  const { hasRole } = useAuthStore()
  const isSuper = hasRole('super_admin')
  const { data, isLoading, error } = useTenants(isSuper)
  const [searchParams, setSearchParams] = useSearchParams()
  const [selectedId, setSelectedId] = useState<string | null>(searchParams.get('id'))
  const [tab, setTab] = useState<Tab>('overview')

  useEffect(() => {
    const id = searchParams.get('id')
    if (id) setSelectedId(id)
  }, [searchParams])

  if (!isSuper) {
    return <p className="muted">Clients is available to super administrators only.</p>
  }

  const selected = (data?.items ?? []).find((t) => t.id === selectedId) ?? null

  const openClient = (t: TenantInfo) => {
    setSelectedId(t.id)
    setTab('overview')
    setSearchParams({ id: t.id })
  }
  const back = () => {
    setSelectedId(null)
    setSearchParams({})
  }

  if (selectedId && !selected && isLoading) {
    return <div className="py-10 text-center muted">Loading…</div>
  }

  if (selected) {
    return <ClientDetail tenant={selected} tab={tab} onTab={setTab} onBack={back} />
  }

  const columns = [
    col.accessor('name', {
      header: 'Client',
      cell: (i) => (
        <button className="link text-left" onClick={() => openClient(i.row.original)}>
          {i.getValue()}
        </button>
      ),
    }),
    col.accessor('slug', { header: 'Slug', cell: (i) => <code className="mono">{i.getValue()}</code> }),
    col.accessor('sector', { header: 'Sector', cell: (i) => i.getValue() ?? '—' }),
    col.display({ id: 'risk', header: 'Risk', cell: (i) => <RiskCell tenantId={i.row.original.id} /> }),
  ]

  return (
    <div>
      <p className="muted mb-3 text-sm">
        Pick a client to see everything correlated to it: assets, scores, cases, threat actors,
        campaigns, observables, dark web and ATT&amp;CK, all in one place. To create or rename a
        client, use Management → Tenants.
      </p>
      <ErrorMessage error={error as Error | null} />
      <DataTable columns={columns} data={data?.items ?? []} isLoading={isLoading} />
    </div>
  )
}

function ClientDetail({
  tenant,
  tab,
  onTab,
  onBack,
}: {
  tenant: TenantInfo
  tab: Tab
  onTab: (t: Tab) => void
  onBack: () => void
}) {
  return (
    <div className="space-y-3">
      <div>
        <button className="link text-xs" onClick={onBack}>← All clients</button>
        <h2 className="text-lg font-semibold">{tenant.name}</h2>
        <p className="muted text-xs">
          <code className="mono">{tenant.slug}</code> · {tenant.sector ?? 'No sector'} ·{' '}
          <code className="mono">{tenant.id}</code>
        </p>
      </div>
      <div className="flex gap-2 overflow-x-auto" role="tablist">
        {TABS.map(([t, label]) => (
          <button
            key={t}
            role="tab"
            aria-selected={tab === t}
            className={tab === t ? 'btn btn-primary' : 'btn btn-ghost'}
            onClick={() => onTab(t)}
          >
            {label}
          </button>
        ))}
      </div>
      <div>
        {tab === 'overview' && <Reports tenantId={tenant.id} />}
        {tab === 'assets' && <Assets tenantId={tenant.id} />}
        {tab === 'scores' && <Scores tenantId={tenant.id} />}
        {tab === 'exposure' && <Exposure tenantId={tenant.id} />}
        {tab === 'cases' && <Cases tenantId={tenant.id} />}
        {tab === 'actors' && <Actors tenantId={tenant.id} />}
        {tab === 'campaigns' && <Campaigns tenantId={tenant.id} />}
        {tab === 'observables' && <Observables tenantId={tenant.id} />}
        {tab === 'darkweb' && <DarkWeb tenantId={tenant.id} />}
        {tab === 'attack' && <AttackHeatmap tenantId={tenant.id} />}
      </div>
    </div>
  )
}
