import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi, beforeEach } from 'vitest'

const mockHasRole = vi.fn()
const createMutate = vi.fn()
const deleteMutate = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
}))
vi.mock('@/api/hooks/useActors', () => ({
  useActors: () => ({
    data: {
      items: [
        { id: 'a1', tenant_id: null, name: 'APT28', aliases: ['Fancy Bear'], description: null, created_at: '' },
        { id: 'a2', tenant_id: 't1', name: 'Mio Gruppo', aliases: null, description: 'nota', created_at: '' },
      ],
      total: 2,
    },
    isLoading: false,
    error: null,
  }),
  useCreateActor: () => ({ mutate: createMutate, reset: vi.fn(), isPending: false, error: null }),
  useUpdateActor: () => ({ mutate: vi.fn(), reset: vi.fn(), isPending: false, error: null }),
  useDeleteActor: () => ({ mutate: deleteMutate, reset: vi.fn(), isPending: false, error: null }),
}))

import { Actors } from '@/pages/Actors'

const renderPage = () =>
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Actors tenantId="t1" />
    </QueryClientProvider>,
  )

beforeEach(() => {
  createMutate.mockClear()
  deleteMutate.mockClear()
})

test('renders actor name and aliases', () => {
  mockHasRole.mockReturnValue(false)
  renderPage()
  expect(screen.getByText('APT28')).toBeInTheDocument()
  expect(screen.getByText('Fancy Bear')).toBeInTheDocument()
})

test('viewer sees no New actor button and no row actions', () => {
  mockHasRole.mockReturnValue(false)
  renderPage()
  expect(screen.queryByRole('button', { name: /new actor/i })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /edit/i })).not.toBeInTheDocument()
})

test('only the tenant own actor can be edited or deleted, not the shared one', () => {
  mockHasRole.mockReturnValue(true)
  renderPage()
  expect(screen.getAllByRole('button', { name: /^edit$/i })).toHaveLength(1)
  expect(screen.getAllByRole('button', { name: /^delete$/i })).toHaveLength(1)
  expect(screen.getByText('shared')).toBeInTheDocument()
})

test('create sends trimmed name, split aliases and null description', () => {
  mockHasRole.mockReturnValue(true)
  renderPage()
  fireEvent.click(screen.getByRole('button', { name: /new actor/i }))
  const create = screen.getByRole('button', { name: /^create$/i })
  expect(create).toBeDisabled() // blank name
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: '  FIN7 ' } })
  fireEvent.change(screen.getByLabelText('Aliases'), { target: { value: 'Carbanak, , Navigator Group' } })
  expect(create).toBeEnabled()
  fireEvent.click(create)
  expect(createMutate).toHaveBeenCalledTimes(1)
  expect(createMutate.mock.calls[0][0]).toEqual({
    name: 'FIN7',
    aliases: ['Carbanak', 'Navigator Group'],
    description: null,
  })
})

test('delete asks for confirmation first', () => {
  mockHasRole.mockReturnValue(true)
  renderPage()
  fireEvent.click(screen.getByRole('button', { name: /^delete$/i }))
  expect(deleteMutate).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: /^confirm$/i }))
  expect(deleteMutate).toHaveBeenCalledWith('a2')
})
