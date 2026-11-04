import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

vi.mock('@/auth/store', () => ({ useAuthStore: () => ({ user: { access_token: 'tok' } }) }))
vi.mock('@/api/hooks/useReports', () => ({
  useQuickReport: () => ({
    data: {
      tenant_id: 't1',
      generated_at: '',
      total_assets: 42,
      critical_assets: 3,
      open_cases: 7,
      top_vulnerabilities: [],
      risk_trend: [],
    },
    isLoading: false,
    error: null,
  }),
}))

import { Reports } from '@/pages/Reports'

test('renders KPI counts', () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Reports tenantId="t1" />
    </QueryClientProvider>,
  )
  expect(screen.getByText('42')).toBeInTheDocument()
  expect(screen.getByText('3')).toBeInTheDocument()
  expect(screen.getByText('7')).toBeInTheDocument()
})
