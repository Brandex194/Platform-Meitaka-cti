import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

vi.mock('@/auth/store', () => ({ useAuthStore: () => ({ user: { access_token: 'tok' } }) }))
vi.mock('@/api/hooks/useCampaigns', () => ({
  useCampaigns: () => ({
    data: {
      items: [{ id: '1', name: 'Operation Sandstorm', threat_actor_id: null, description: 'Spear phishing campaign targeting energy sector', created_at: '' }],
      total: 1,
    },
    isLoading: false,
    error: null,
  }),
}))

import { Campaigns } from '@/pages/Campaigns'

test('renders campaign name', () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Campaigns />
    </QueryClientProvider>,
  )
  expect(screen.getByText('Operation Sandstorm')).toBeInTheDocument()
})
