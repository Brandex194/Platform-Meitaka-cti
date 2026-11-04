import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

vi.mock('@/auth/store', () => ({ useAuthStore: () => ({ user: { access_token: 'tok' } }) }))
vi.mock('@/api/hooks/useActors', () => ({
  useActors: () => ({
    data: {
      items: [{ id: '1', name: 'APT28', aliases: ['Fancy Bear'], description: null, created_at: '' }],
      total: 1,
    },
    isLoading: false,
    error: null,
  }),
}))

import { Actors } from '@/pages/Actors'

test('renders actor name and aliases', () => {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Actors />
    </QueryClientProvider>,
  )
  expect(screen.getByText('APT28')).toBeInTheDocument()
  expect(screen.getByText('Fancy Bear')).toBeInTheDocument()
})
