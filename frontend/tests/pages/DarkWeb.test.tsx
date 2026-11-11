import { render, screen, fireEvent, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

const mockHasRole = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
}))
vi.mock('@/api/hooks/useObservations', () => ({
  useObservations: () => ({
    data: {
      items: [{ id: '1', tenant_id: 't1', asset_id: null, event_type: 'darkweb', payload: { source: 'forum.onion', context: 'credentials leak', severity: 'high', status: 'new' }, created_at: '' }],
      total: 1,
    },
    isLoading: false,
    error: null,
  }),
}))
const createFinding = vi.fn()
const createLeak = vi.fn()
const setStatus = vi.fn()
const idle = { mutate: vi.fn(), isPending: false, error: null }
vi.mock('@/api/hooks/useDarkWeb', () => ({
  useLeaks: () => ({
    data: { items: [{ id: 'l1', email_hash: 'abcdef0123456789', breach_name: 'BigBreach', pwn_count: 1000, created_at: '' }] },
    isLoading: false, error: null,
  }),
  useCreateFinding: () => ({ ...idle, mutate: createFinding }),
  useSetFindingStatus: () => ({ ...idle, mutate: setStatus }),
  useDeleteFinding: () => idle,
  useCreateLeak: () => ({ ...idle, mutate: createLeak }),
  useDeleteLeak: () => idle,
}))

import { DarkWeb } from '@/pages/DarkWeb'

const show = () =>
  render(<QueryClientProvider client={new QueryClient()}><DarkWeb tenantId="t1" /></QueryClientProvider>)

beforeEach(() => { vi.clearAllMocks(); mockHasRole.mockReturnValue(false) })

test('renders the recorded finding without write controls for a viewer', () => {
  show()
  expect(screen.getByText('forum.onion')).toBeInTheDocument()
  expect(screen.getByText('credentials leak')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Add finding' })).toBeNull()
})

test('leaks tab shows the breach and only a short hash', () => {
  show()
  fireEvent.click(screen.getByRole('tab', { name: 'Leaks' }))
  expect(screen.getByText('BigBreach')).toBeInTheDocument()
  expect(screen.getByText('abcdef012345…')).toBeInTheDocument()
})

test('analyst adds a finding', () => {
  mockHasRole.mockImplementation((r: string) => r === 'analyst')
  show()
  fireEvent.click(screen.getByRole('button', { name: 'Add finding' }))
  const dlg = document.querySelector('.modal') as HTMLElement
  fireEvent.change(within(dlg).getByLabelText('Source'), { target: { value: 'paste.site' } })
  fireEvent.change(within(dlg).getByLabelText('What was found'), { target: { value: 'dump' } })
  fireEvent.submit(dlg)
  expect(createFinding).toHaveBeenCalledWith({ source: 'paste.site', context: 'dump', severity: 'medium' }, expect.anything())
})

test('analyst changes a finding status and adds a leak', () => {
  mockHasRole.mockImplementation((r: string) => r === 'analyst')
  show()
  fireEvent.change(screen.getByLabelText('Status of forum.onion'), { target: { value: 'reviewed' } })
  expect(setStatus).toHaveBeenCalledWith({ id: '1', status: 'reviewed' })
  fireEvent.click(screen.getByRole('tab', { name: 'Leaks' }))
  fireEvent.click(screen.getByRole('button', { name: 'Add leak' }))
  const dlg = document.querySelector('.modal') as HTMLElement
  fireEvent.change(within(dlg).getByLabelText('Email'), { target: { value: 'a@b.co' } })
  fireEvent.change(within(dlg).getByLabelText('Breach name'), { target: { value: 'X' } })
  fireEvent.submit(dlg)
  expect(createLeak).toHaveBeenCalledWith({ email: 'a@b.co', breach_name: 'X' }, expect.anything())
})
