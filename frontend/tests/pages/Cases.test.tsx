import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

const mockHasRole = vi.fn()
const mockUpdate = vi.fn()
const mockAddNote = vi.fn()
const mockDeleteNote = vi.fn()
const mockUseCases = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({
    user: { access_token: 'tok', profile: { sub: 'me-1' } },
    hasRole: mockHasRole,
  }),
}))

const base = { created_at: '2026-11-09T10:00:00Z', description: 'desc', created_by: null, updated_at: '', closed_at: null }
const CASES = [
  { ...base, id: 'c1', title: 'Test Case Alpha', status: 'open', severity: 'high', due_at: '2026-11-10T10:00:00Z', sla_status: 'at_risk' },
  { ...base, id: 'c2', title: 'Test Case Beta', status: 'closed', severity: 'low', due_at: null, sla_status: 'met' },
]
const NOTES = [
  { id: 'n1', case_id: 'c1', author_id: 'me-1', body: 'my note', created_at: '2026-11-09T11:00:00Z' },
  { id: 'n2', case_id: 'c1', author_id: 'other', body: 'their note', created_at: '2026-11-09T12:00:00Z' },
]
const EVENTS = [
  { id: 'e1', case_id: 'c1', actor_id: null, event_type: 'status_changed', payload: { from: 'open', to: 'in_progress' }, created_at: '2026-11-09T11:00:00Z' },
]
vi.mock('@/api/hooks/useCases', () => ({
  useCases: (...a: unknown[]) => mockUseCases(...a),
  useCreateCase: () => ({ mutate: vi.fn(), isPending: false }),
  useUpdateCase: () => ({ mutate: mockUpdate, isPending: false }),
  useDeleteCase: () => ({ mutate: vi.fn(), isPending: false }),
  useCaseNotes: () => ({ data: { items: NOTES }, isLoading: false }),
  useCaseTimeline: () => ({ data: { items: EVENTS }, isLoading: false }),
  useAddNote: () => ({ mutate: mockAddNote, isPending: false }),
  useDeleteNote: () => ({ mutate: mockDeleteNote, isPending: false }),
}))

import { Cases } from '@/pages/Cases'

const show = () =>
  render(<QueryClientProvider client={new QueryClient()}><Cases tenantId="t1" /></QueryClientProvider>)

beforeEach(() => {
  vi.clearAllMocks()
  mockUseCases.mockReturnValue({ data: { items: CASES, total: 2 }, isLoading: false })
})

test('renders case rows with SLA badges', () => {
  mockHasRole.mockReturnValue(false)
  show()
  expect(screen.getByText('Test Case Alpha')).toBeInTheDocument()
  expect(screen.getByText('Test Case Beta')).toBeInTheDocument()
  expect(screen.getByText('at risk')).toBeInTheDocument()
  expect(screen.getByText('met')).toBeInTheDocument()
})

test('New Case button hidden for viewer', () => {
  mockHasRole.mockReturnValue(false)
  show()
  expect(screen.queryByRole('button', { name: /new case/i })).not.toBeInTheDocument()
})

test('New Case button visible for analyst', () => {
  mockHasRole.mockImplementation((r: string) => r === 'analyst')
  show()
  expect(screen.getByRole('button', { name: /new case/i })).toBeInTheDocument()
})

test('status tab passes the filter to the query', () => {
  mockHasRole.mockReturnValue(false)
  show()
  fireEvent.click(screen.getByRole('tab', { name: 'In analysis' }))
  expect(mockUseCases).toHaveBeenLastCalledWith('t1', 'in_progress')
})

test('clicking a title opens detail with notes and timeline', () => {
  mockHasRole.mockReturnValue(false)
  show()
  fireEvent.click(screen.getByRole('button', { name: 'Test Case Alpha' }))
  const panel = screen.getByLabelText('Case detail')
  expect(panel).toHaveTextContent('my note')
  fireEvent.click(screen.getByRole('button', { name: 'Timeline' }))
  expect(panel).toHaveTextContent('Status: Open → In analysis')
})

test('viewer cannot add notes or change status', () => {
  mockHasRole.mockReturnValue(false)
  show()
  fireEvent.click(screen.getByRole('button', { name: 'Test Case Alpha' }))
  expect(screen.queryByLabelText('New note')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Delete note' })).not.toBeInTheDocument()
})

test('analyst adds a note and runs quick actions; deletes only own notes', () => {
  mockHasRole.mockImplementation((r: string) => r === 'analyst')
  show()
  fireEvent.click(screen.getByRole('button', { name: 'Test Case Alpha' }))
  fireEvent.change(screen.getByLabelText('New note'), { target: { value: '  hello  ' } })
  fireEvent.click(screen.getByRole('button', { name: 'Add note' }))
  expect(mockAddNote.mock.calls[0][0]).toBe('hello')
  fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
  expect(mockUpdate).toHaveBeenCalledWith({ id: 'c1', status: 'in_progress' })
  fireEvent.click(screen.getByRole('button', { name: 'False positive', hidden: false }))
  expect(mockUpdate).toHaveBeenLastCalledWith({ id: 'c1', status: 'false_positive' })
  expect(screen.getAllByRole('button', { name: 'Delete note' })).toHaveLength(1)
})

test('closed case offers Reopen', () => {
  mockHasRole.mockImplementation((r: string) => r === 'analyst')
  show()
  fireEvent.click(screen.getByRole('button', { name: 'Test Case Beta' }))
  fireEvent.click(screen.getByRole('button', { name: 'Reopen' }))
  expect(mockUpdate).toHaveBeenCalledWith({ id: 'c2', status: 'open' })
})

test('tenant admin can delete any note', () => {
  mockHasRole.mockImplementation((r: string) => r === 'tenant_admin')
  show()
  fireEvent.click(screen.getByRole('button', { name: 'Test Case Alpha' }))
  expect(screen.getAllByRole('button', { name: 'Delete note' })).toHaveLength(2)
})
