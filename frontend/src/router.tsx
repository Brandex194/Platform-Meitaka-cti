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
          { path: '/actors', element: <Actors /> },
          { path: '/campaigns', element: <Campaigns /> },
          { path: '/observables', element: <TenantPage Page={Observables} /> },
          { path: '/dark-web', element: <TenantPage Page={DarkWeb} /> },
          { path: '/reports', element: <TenantPage Page={Reports} /> },
        ],
      },
    ],
  },
])
