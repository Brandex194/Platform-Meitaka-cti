import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'

const mockHasRole = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
}))

const TENANTS = [
  { id: 't1', name: 'Acme Bank', slug: 'acme', sector: 'Finance', created_at: '' },
  { id: 't2', name: 'Beta Corp', slug: 'beta', sector: null, created_at: '' },
]
vi.mock('@/api/hooks/useManagement', () => ({
  useTenants: () => ({ data: { items: TENANTS, total: 2 }, isLoading: false, error: null }),
}))
let REPORT: Record<string, unknown> = {
  tenant_id: 't1', generated_at: '', total_assets: 5, critical_assets: 1, open_cases: 2,
  assets_by_level: { critical: 1, high: 0, medium: 0, low: 0 }, unscored_assets: 0,
  top_assets: [], sla_breached_cases: 0, sla_at_risk_cases: 0, kev_vulnerabilities: 0,
  leaks_total: 0, darkweb_findings_new: 0, top_vulnerabilities: [], risk_trend: [],
}
vi.mock('@/api/hooks/useReports', () => ({
  useQuickReport: () => ({ data: REPORT, isLoading: false, error: null }),
}))

import { Clients } from '@/pages/Clients'

const show = (initial = '/clients') =>
  render(
    <MemoryRouter initialEntries={[initial]}>
      <QueryClientProvider client={new QueryClient()}><Clients /></QueryClientProvider>
    </MemoryRouter>,
  )

beforeEach(() => {
  mockHasRole.mockReturnValue(false)
  REPORT = {
    tenant_id: 't1', generated_at: '', total_assets: 5, critical_assets: 1, open_cases: 2,
    assets_by_level: { critical: 1, high: 0, medium: 0, low: 0 }, unscored_assets: 0,
    top_assets: [], sla_breached_cases: 0, sla_at_risk_cases: 0, kev_vulnerabilities: 0,
    leaks_total: 0, darkweb_findings_new: 0, top_vulnerabilities: [], risk_trend: [],
  }
})

test('non super admin sees a restricted message', () => {
  show()
  expect(screen.getByText(/super administrators only/i)).toBeInTheDocument()
})

test('super admin sees the client list and opens one by clicking its name', () => {
  mockHasRole.mockImplementation((r: string) => r === 'super_admin')
  show()
  expect(screen.getByText('Acme Bank')).toBeInTheDocument()
  expect(screen.getByText('Beta Corp')).toBeInTheDocument()
  fireEvent.click(screen.getByText('Acme Bank'))
  expect(screen.getByRole('tab', { name: 'Overview' })).toBeInTheDocument()
  expect(screen.getByText(/Finance/)).toBeInTheDocument()
})

test('switching tabs changes the selected tab', () => {
  mockHasRole.mockImplementation((r: string) => r === 'super_admin')
  show()
  fireEvent.click(screen.getByText('Acme Bank'))
  fireEvent.click(screen.getByRole('tab', { name: 'Assets' }))
  expect(screen.getByRole('tab', { name: 'Assets' })).toHaveAttribute('aria-selected', 'true')
  expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'false')
})

test('back button returns to the client list', () => {
  mockHasRole.mockImplementation((r: string) => r === 'super_admin')
  show()
  fireEvent.click(screen.getByText('Acme Bank'))
  fireEvent.click(screen.getByText('← All clients'))
  expect(screen.getByText('Beta Corp')).toBeInTheDocument()
  expect(screen.queryByRole('tab', { name: 'Overview' })).toBeNull()
})

test('a ?id= query param opens that client directly', () => {
  mockHasRole.mockImplementation((r: string) => r === 'super_admin')
  show('/clients?id=t2')
  expect(screen.getByRole('tab', { name: 'Overview' })).toBeInTheDocument()
  expect(screen.getByText(/No sector/)).toBeInTheDocument()
})

test('the client list shows a risk gauge per row, from real data', () => {
  REPORT = { ...REPORT, top_assets: [{ asset_id: 'a1', hostname: 'web-01', ip: null, value: 0.8, level: 'high' }] }
  mockHasRole.mockImplementation((r: string) => r === 'super_admin')
  show()
  expect(screen.getAllByRole('img', { name: /Risk score 0.80, high/ }).length).toBe(2)
})

test('a client with no scored assets shows "No data" in the risk column', () => {
  mockHasRole.mockImplementation((r: string) => r === 'super_admin')
  show()
  expect(screen.getAllByText('No data').length).toBe(2)
})
