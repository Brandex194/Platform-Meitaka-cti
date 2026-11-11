import { render, screen, fireEvent, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

const mockHasRole = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
}))

const linkMutate = vi.fn()
const unlinkMutate = vi.fn()
let graph: Record<string, unknown>
const GRAPH = {
  nodes: [
    { id: 'a1', type: 'threat_actor', label: 'APT-G', own: true, detail: null },
    { id: 'c1', type: 'campaign', label: 'Op G', own: true, detail: null },
    { id: 'c2', type: 'campaign', label: 'Shared Op', own: false, detail: null },
    { id: 'i1', type: 'indicator', label: 'g.example', own: true, detail: 'domain' },
  ],
  edges: [
    { source: 'c1', target: 'a1', type: 'attributed-to' },
    { source: 'i1', target: 'c1', type: 'indicates' },
  ],
  indicators_total: 1,
  truncated: false,
}
vi.mock('@/api/hooks/useGraph', () => ({
  useGraph: () => ({ data: graph, isLoading: false, error: null }),
  useLinkableIndicators: () => ({
    data: { items: [{ id: 'i1', ioc_type: 'domain', value: 'g.example' }, { id: 'i2', ioc_type: 'ip', value: '203.0.113.9' }] },
  }),
  useLinkIndicator: () => ({ mutate: linkMutate, isPending: false, error: null }),
  useUnlinkIndicator: () => ({ mutate: unlinkMutate, error: null }),
}))

import { KnowledgeGraph } from '@/pages/KnowledgeGraph'

const show = () =>
  render(<QueryClientProvider client={new QueryClient()}><KnowledgeGraph tenantId="t1" /></QueryClientProvider>)
const node = (name: string) => screen.getByRole('button', { name })

beforeEach(() => {
  vi.clearAllMocks()
  graph = GRAPH
  mockHasRole.mockReturnValue(false)
})

test('empty graph explains what to do', () => {
  graph = { nodes: [], edges: [], indicators_total: 0, truncated: false }
  show()
  expect(screen.getByText(/Nothing to show yet/)).toBeInTheDocument()
})

test('draws every node and marks shared ones', () => {
  show()
  expect(node('threat actor APT-G')).toBeInTheDocument()
  expect(node('campaign Op G')).toBeInTheDocument()
  expect(node('campaign Shared Op')).toBeInTheDocument()
  expect(node('indicator g.example')).toBeInTheDocument()
})

test('selecting an actor lists its campaigns; selecting a campaign shows actor and indicators', () => {
  show()
  fireEvent.click(node('threat actor APT-G'))
  const panel = screen.getByLabelText('Node details')
  expect(within(panel).getByText('Op G')).toBeInTheDocument()
  fireEvent.click(node('campaign Op G'))
  expect(within(screen.getByLabelText('Node details')).getByText('APT-G')).toBeInTheDocument()
  expect(within(screen.getByLabelText('Node details')).getByText('domain: g.example')).toBeInTheDocument()
})

test('keyboard can select a node', () => {
  show()
  fireEvent.keyDown(node('campaign Op G'), { key: 'Enter' })
  expect(screen.getByLabelText('Node details')).toBeInTheDocument()
})

test('viewer cannot connect or unlink', () => {
  show()
  fireEvent.click(node('campaign Op G'))
  expect(screen.queryByRole('button', { name: 'Connect' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Unlink' })).not.toBeInTheDocument()
})

test('analyst connects an unlinked indicator and unlinks a linked one', () => {
  mockHasRole.mockImplementation((r: string) => r === 'analyst')
  show()
  fireEvent.click(node('campaign Op G'))
  const select = screen.getByLabelText('Indicator to connect') as HTMLSelectElement
  const options = Array.from(select.options).map((o) => o.textContent)
  expect(options).toContain('ip: 203.0.113.9')
  expect(options).not.toContain('domain: g.example') // already connected
  expect(screen.getByRole('button', { name: 'Connect' })).toBeDisabled()
  fireEvent.change(select, { target: { value: 'i2' } })
  fireEvent.click(screen.getByRole('button', { name: 'Connect' }))
  expect(linkMutate.mock.calls[0][0]).toEqual({ campaignId: 'c1', indicatorId: 'i2' })
  fireEvent.click(screen.getByRole('button', { name: 'Unlink' }))
  expect(unlinkMutate).toHaveBeenCalledWith({ campaignId: 'c1', indicatorId: 'i1' })
})

test('truncation is announced', () => {
  graph = { ...GRAPH, indicators_total: 900, truncated: true }
  show()
  expect(screen.getByText(/900 indicators are connected/)).toBeInTheDocument()
})
