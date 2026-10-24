import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

const mockHasRole = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
}))
vi.mock('@/api/hooks/useExposure', () => ({
  useExposure: () => ({
    data: { items: [{ id: 'e1', status: 'active', epss_score: 0.42, updated_at: '' }], total: 1 },
    isLoading: false,
  }),
  usePatchExposure: () => ({ mutate: vi.fn(), isPending: false }),
}))

import { Exposure } from '@/pages/Exposure'

test('resolve button visible for analyst', () => {
  mockHasRole.mockImplementation((r: string) => ['analyst'].includes(r))
  render(<QueryClientProvider client={new QueryClient()}><Exposure tenantId="t1" /></QueryClientProvider>)
  expect(screen.getAllByRole('button', { name: /resolve/i }).length).toBeGreaterThan(0)
})

test('resolve button hidden for viewer', () => {
  mockHasRole.mockReturnValue(false)
  render(<QueryClientProvider client={new QueryClient()}><Exposure tenantId="t1" /></QueryClientProvider>)
  expect(screen.queryByRole('button', { name: /resolve/i })).not.toBeInTheDocument()
})
