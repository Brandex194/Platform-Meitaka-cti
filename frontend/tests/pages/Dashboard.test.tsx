import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

vi.mock('recharts', () => ({
  BarChart: () => null,
  Bar: () => null,
  XAxis: () => null,
  YAxis: () => null,
  Tooltip: () => null,
  ResponsiveContainer: () => null,
}))

vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: () => true }),
}))
vi.mock('@/api/hooks/useDashboard', () => ({
  useDashboard: () => ({
    data: {
      open_cases: 3,
      critical_scores: 1,
      active_exposures: 7,
      recent_events: [],
      scores_by_level: [{ level: 'high', count: 2 }],
    },
    isLoading: false,
    error: null,
  }),
}))

import { Dashboard } from '@/pages/Dashboard'

test('shows KPI counts', () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Dashboard tenantId="t1" />
    </QueryClientProvider>,
  )
  expect(screen.getByText('3')).toBeInTheDocument()
  expect(screen.getByText('7')).toBeInTheDocument()
})
