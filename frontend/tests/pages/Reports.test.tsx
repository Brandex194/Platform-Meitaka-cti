import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

let REPORT: Record<string, unknown> = {
  tenant_id: 't1',
  generated_at: '',
  total_assets: 42,
  critical_assets: 3,
  open_cases: 7,
  assets_by_level: { critical: 3, high: 0, medium: 0, low: 0 },
  unscored_assets: 39,
  top_assets: [{ asset_id: 'a1aaaaaa', hostname: 'web-01', ip: null, value: 0.91, level: 'critical' }],
  sla_breached_cases: 2,
  sla_at_risk_cases: 1,
  kev_vulnerabilities: 5,
  leaks_total: 4,
  darkweb_findings_new: 6,
  top_vulnerabilities: [],
  risk_trend: [],
}
vi.mock('@/auth/store', () => ({ useAuthStore: () => ({ user: { access_token: 'tok' } }) }))
vi.mock('@/api/hooks/useReports', () => ({
  useQuickReport: () => ({ data: REPORT, isLoading: false, error: null }),
}))

import { Reports } from '@/pages/Reports'

beforeEach(() => {
  REPORT = {
    tenant_id: 't1', generated_at: '', total_assets: 42, critical_assets: 3, open_cases: 7,
    assets_by_level: { critical: 3, high: 0, medium: 0, low: 0 }, unscored_assets: 39,
    top_assets: [{ asset_id: 'a1aaaaaa', hostname: 'web-01', ip: null, value: 0.91, level: 'critical' }],
    sla_breached_cases: 2, sla_at_risk_cases: 1, kev_vulnerabilities: 5, leaks_total: 4,
    darkweb_findings_new: 6, top_vulnerabilities: [], risk_trend: [],
  }
})

test('renders KPI counts', () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Reports tenantId="t1" />
    </QueryClientProvider>,
  )
  expect(screen.getByText('42')).toBeInTheDocument()
  expect(screen.getAllByText('3').length).toBeGreaterThan(0)
  expect(screen.getByText('7')).toBeInTheDocument()
})

test('shows the new sections and exports a CSV', () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Reports tenantId="t1" />
    </QueryClientProvider>,
  )
  expect(screen.getAllByText('web-01').length).toBeGreaterThan(0)
  expect(screen.getByText('Cases Past SLA').previousSibling).toHaveTextContent('2')
  expect(screen.getByText('Vulnerabilities in KEV').previousSibling).toHaveTextContent('5')
  expect(screen.getByRole('img', { name: 'Assets by risk level' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Download CSV' })).toBeInTheDocument()
})

test('shows a risk gauge for the highest-risk asset', () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Reports tenantId="t1" />
    </QueryClientProvider>,
  )
  expect(screen.getByRole('img', { name: /Risk score 0.91, critical/ })).toBeInTheDocument()
  expect(screen.getByText('Highest-risk asset')).toBeInTheDocument()
})

test('reasoning box only states facts already in the report', () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Reports tenantId="t1" />
    </QueryClientProvider>,
  )
  expect(screen.getByText('Why this needs attention')).toBeInTheDocument()
  expect(screen.getByText(/5 vulnerabilities in CISA KEV/)).toBeInTheDocument()
  expect(screen.getByText(/3 assets at critical risk level/)).toBeInTheDocument()
  expect(screen.getByText(/2 cases past SLA/)).toBeInTheDocument()
  expect(screen.getByText(/4 leaked identities on record/)).toBeInTheDocument()
  expect(screen.getByText(/6 new dark web findings not yet reviewed/)).toBeInTheDocument()
})

test('a clean report shows no reasoning box', () => {
  REPORT = { ...REPORT, critical_assets: 0, sla_breached_cases: 0, kev_vulnerabilities: 0, leaks_total: 0, darkweb_findings_new: 0 }
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Reports tenantId="t1" />
    </QueryClientProvider>,
  )
  expect(screen.queryByText('Why this needs attention')).toBeNull()
})
