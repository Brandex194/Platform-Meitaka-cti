import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

const mockHasRole = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
}))
vi.mock('@/api/hooks/useCases', () => ({
  useCases: () => ({
    data: {
      items: [
        { id: 'c1', title: 'Test Case Alpha', status: 'open', severity: 'high', created_at: '', description: null, created_by: null, updated_at: '' },
        { id: 'c2', title: 'Test Case Beta', status: 'closed', severity: 'low', created_at: '', description: null, created_by: null, updated_at: '' },
      ],
      total: 2,
    },
    isLoading: false,
  }),
  useCreateCase: () => ({ mutate: vi.fn(), isPending: false }),
  useUpdateCase: () => ({ mutate: vi.fn(), isPending: false }),
  useDeleteCase: () => ({ mutate: vi.fn(), isPending: false }),
}))

import { Cases } from '@/pages/Cases'

test('renders case rows', () => {
  mockHasRole.mockReturnValue(false)
  render(<QueryClientProvider client={new QueryClient()}><Cases tenantId="t1" /></QueryClientProvider>)
  expect(screen.getByText('Test Case Alpha')).toBeInTheDocument()
  expect(screen.getByText('Test Case Beta')).toBeInTheDocument()
})

test('New Case button hidden for viewer', () => {
  mockHasRole.mockReturnValue(false)
  render(<QueryClientProvider client={new QueryClient()}><Cases tenantId="t1" /></QueryClientProvider>)
  expect(screen.queryByRole('button', { name: /new case/i })).not.toBeInTheDocument()
})

test('New Case button visible for analyst', () => {
  mockHasRole.mockImplementation((r: string) => r === 'analyst')
  render(<QueryClientProvider client={new QueryClient()}><Cases tenantId="t1" /></QueryClientProvider>)
  expect(screen.getByRole('button', { name: /new case/i })).toBeInTheDocument()
})
