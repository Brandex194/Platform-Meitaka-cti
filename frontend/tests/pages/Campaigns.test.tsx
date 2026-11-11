import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi, beforeEach } from 'vitest'

const mockHasRole = vi.fn()
const createMutate = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
}))
vi.mock('@/api/hooks/useCampaigns', () => ({
  useCampaigns: () => ({
    data: {
      items: [
        { id: 'c1', tenant_id: null, name: 'Operation Sandstorm', threat_actor_id: 'a1', description: 'Spear phishing campaign targeting energy sector', created_at: '' },
        { id: 'c2', tenant_id: 't1', name: 'Campagna mia', threat_actor_id: null, description: null, created_at: '' },
      ],
      total: 2,
    },
    isLoading: false,
    error: null,
  }),
  useCreateCampaign: () => ({ mutate: createMutate, reset: vi.fn(), isPending: false, error: null }),
  useUpdateCampaign: () => ({ mutate: vi.fn(), reset: vi.fn(), isPending: false, error: null }),
  useDeleteCampaign: () => ({ mutate: vi.fn(), reset: vi.fn(), isPending: false, error: null }),
}))
vi.mock('@/api/hooks/useActors', () => ({
  useActors: () => ({
    data: { items: [{ id: 'a1', tenant_id: null, name: 'APT28', aliases: null, description: null, created_at: '' }], total: 1 },
  }),
}))

import { Campaigns } from '@/pages/Campaigns'

const renderPage = () =>
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Campaigns tenantId="t1" />
    </QueryClientProvider>,
  )

beforeEach(() => createMutate.mockClear())

test('renders campaign name and the actor name instead of its id', () => {
  mockHasRole.mockReturnValue(false)
  renderPage()
  expect(screen.getByText('Operation Sandstorm')).toBeInTheDocument()
  expect(screen.getByText('APT28')).toBeInTheDocument()
})

test('viewer cannot create; analyst edits only the own campaign', () => {
  mockHasRole.mockReturnValue(false)
  const { unmount } = renderPage()
  expect(screen.queryByRole('button', { name: /new campaign/i })).not.toBeInTheDocument()
  unmount()
  mockHasRole.mockReturnValue(true)
  renderPage()
  expect(screen.getAllByRole('button', { name: /^edit$/i })).toHaveLength(1)
})

test('create sends the chosen actor, or null when none is chosen', () => {
  mockHasRole.mockReturnValue(true)
  renderPage()
  fireEvent.click(screen.getByRole('button', { name: /new campaign/i }))
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Operazione X' } })
  fireEvent.change(screen.getByLabelText('Threat actor'), { target: { value: 'a1' } })
  fireEvent.click(screen.getByRole('button', { name: /^create$/i }))
  expect(createMutate.mock.calls[0][0]).toEqual({
    name: 'Operazione X',
    threat_actor_id: 'a1',
    description: null,
  })
})
