import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

vi.mock('@/auth/store', () => ({ useAuthStore: () => ({ user: { access_token: 'tok' } }) }))
vi.mock('@/api/hooks/useIndicators', () => ({
  useIndicators: () => ({
    data: {
      items: [{ id: '1', tenant_id: 't1', ioc_type: 'ip', value: '1.2.3.4', confidence: 0.9, created_at: '' }],
      total: 1,
    },
    isLoading: false,
    error: null,
  }),
}))

import { Observables } from '@/pages/Observables'

test('renders indicator value and type', () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Observables tenantId="t1" />
    </QueryClientProvider>,
  )
  expect(screen.getByText('1.2.3.4')).toBeInTheDocument()
  expect(screen.getAllByText('ip').length).toBeGreaterThan(0)
})
