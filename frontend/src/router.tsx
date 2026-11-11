import type { ComponentType } from 'react'
import { createBrowserRouter } from 'react-router-dom'
import { AuthGuard } from './auth/AuthGuard'
import { Callback } from './auth/Callback'
import { Layout } from './components/Layout'
import { useAuthStore } from './auth/store'
import { Dashboard } from './pages/Dashboard'
import { Assets } from './pages/Assets'
import { Scores } from './pages/Scores'
import { Exposure } from './pages/Exposure'
import { Analysis } from './pages/Analysis'
import { Cases } from './pages/Cases'
import { Actors } from './pages/Actors'
import { Campaigns } from './pages/Campaigns'
import { Observables } from './pages/Observables'
import { DarkWeb } from './pages/DarkWeb'
import { Reports } from './pages/Reports'
import { Management } from './pages/Management'
import { Stix } from './pages/Stix'
import { KnowledgeGraph } from './pages/KnowledgeGraph'
import { AttackHeatmap } from './pages/AttackHeatmap'
import { QuickReport } from './pages/QuickReport'
import { Scanner } from './pages/Scanner'
import { RedTeam } from './pages/RedTeam'
import { Connectors } from './pages/Connectors'
import { Clients } from './pages/Clients'

function TenantPage({ Page }: { Page: ComponentType<{ tenantId: string }> }) {
  const { user } = useAuthStore()
  const tenantId: string = (user?.profile as any)?.tenant_id ?? ''
  return <Page tenantId={tenantId} />
}

export const router = createBrowserRouter([
  { path: '/callback', element: <Callback /> },
  {
    element: <AuthGuard />,
    children: [
      {
        element: <Layout />,
        children: [
          { path: '/', element: <TenantPage Page={Dashboard} /> },
          { path: '/assets', element: <TenantPage Page={Assets} /> },
          { path: '/scores', element: <TenantPage Page={Scores} /> },
          { path: '/exposure', element: <TenantPage Page={Exposure} /> },
          { path: '/analysis', element: <TenantPage Page={Analysis} /> },
          { path: '/cases', element: <TenantPage Page={Cases} /> },
          { path: '/actors', element: <TenantPage Page={Actors} /> },
          { path: '/campaigns', element: <TenantPage Page={Campaigns} /> },
          { path: '/observables', element: <TenantPage Page={Observables} /> },
          { path: '/dark-web', element: <TenantPage Page={DarkWeb} /> },
          { path: '/reports', element: <TenantPage Page={Reports} /> },
          { path: '/graph', element: <TenantPage Page={KnowledgeGraph} /> },
          { path: '/attack', element: <TenantPage Page={AttackHeatmap} /> },
          { path: '/stix', element: <TenantPage Page={Stix} /> },
          { path: '/management', element: <TenantPage Page={Management} /> },
          { path: '/clients', element: <Clients /> },
          { path: '/quick-report', element: <TenantPage Page={QuickReport} /> },
          { path: '/scanner', element: <TenantPage Page={Scanner} /> },
          { path: '/redteam', element: <TenantPage Page={RedTeam} /> },
          { path: '/connectors', element: <TenantPage Page={Connectors} /> },
        ],
      },
    ],
  },
])
