import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

vi.mock('@/auth/store', () => ({ useAuthStore: () => ({ user: { access_token: 'tok' } }) }))
vi.mock('@/api/hooks/useObservations', () => ({
  useObservations: () => ({
    data: {
      items: [{ id: '1', tenant_id: 't1', asset_id: null, event_type: 'darkweb', payload: { source: 'forum.onion', context: 'credentials leak' }, created_at: '' }],
      total: 1,
    },
    isLoading: false,
    error: null,
  }),
}))

import { DarkWeb } from '@/pages/DarkWeb'

test('renders dark web observation', () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <DarkWeb tenantId="t1" />
    </QueryClientProvider>,
  )
  expect(screen.getByText('forum.onion')).toBeInTheDocument()
  expect(screen.getByText('credentials leak')).toBeInTheDocument()
})
