import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi, beforeEach } from 'vitest'

const mockHasRole = vi.fn()
const createMutate = vi.fn()
const deleteMutate = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
}))
vi.mock('@/api/hooks/useIndicators', () => ({
  useIndicators: () => ({
    data: {
      items: [
        { id: '1', tenant_id: 't1', ioc_type: 'ip', value: '1.2.3.4', confidence: 0.9, created_at: '' },
        { id: '2', tenant_id: null, ioc_type: 'domain', value: 'feed.example', confidence: null, created_at: '' },
      ],
      total: 2,
    },
    isLoading: false,
    error: null,
  }),
  useCreateIndicator: () => ({ mutate: createMutate, reset: vi.fn(), isPending: false, error: null }),
  useDeleteIndicator: () => ({ mutate: deleteMutate, reset: vi.fn(), isPending: false, error: null }),
}))

const enrichMutate = vi.fn()
vi.mock('@/api/hooks/useIntegrations', () => ({
  useEnrichments: () => ({
    data: { items: [{ indicator_id: '1', provider: 'virustotal', status: 'ok', malicious: 3, suspicious: 1, harmless: 60, undetected: 6, reputation: 0, analysis_date: null, permalink: 'https://www.virustotal.com/gui/ip-address/1.2.3.4', fetched_at: '' }] },
  }),
  useEnrichIndicator: () => ({ mutate: enrichMutate, isPending: false, error: null }),
}))

import { Observables } from '@/pages/Observables'

const renderPage = () =>
  render(
    <QueryClientProvider client={new QueryClient()}>
      <Observables tenantId="t1" />
    </QueryClientProvider>,
  )

beforeEach(() => {
  createMutate.mockClear()
  deleteMutate.mockClear()
})

test('renders indicator value and type', () => {
  mockHasRole.mockReturnValue(false)
  renderPage()
  expect(screen.getByText('1.2.3.4')).toBeInTheDocument()
  expect(screen.getAllByText('ip').length).toBeGreaterThan(0)
})

test('viewer cannot add; analyst can delete only the own row, not the feed one', () => {
  mockHasRole.mockReturnValue(false)
  const { unmount } = renderPage()
  expect(screen.queryByRole('button', { name: /add observable/i })).not.toBeInTheDocument()
  unmount()
  mockHasRole.mockReturnValue(true)
  renderPage()
  expect(screen.getAllByRole('button', { name: /^delete$/i })).toHaveLength(1)
})

test('add converts confidence from percent to 0-1', () => {
  mockHasRole.mockReturnValue(true)
  renderPage()
  fireEvent.click(screen.getByRole('button', { name: /add observable/i }))
  fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'domain' } })
  fireEvent.change(screen.getByLabelText('Value'), { target: { value: ' evil.example ' } })
  fireEvent.change(screen.getByLabelText('Confidence'), { target: { value: '85' } })
  fireEvent.click(screen.getByRole('button', { name: /^add$/i }))
  expect(createMutate.mock.calls[0][0]).toEqual({
    ioc_type: 'domain',
    value: 'evil.example',
    confidence: 0.85,
  })
})

test('add is blocked when confidence is out of range', () => {
  mockHasRole.mockReturnValue(true)
  renderPage()
  fireEvent.click(screen.getByRole('button', { name: /add observable/i }))
  fireEvent.change(screen.getByLabelText('Value'), { target: { value: '1.2.3.4' } })
  fireEvent.change(screen.getByLabelText('Confidence'), { target: { value: '150' } })
  expect(screen.getByRole('button', { name: /^add$/i })).toBeDisabled()
  expect(screen.getByText(/from 0 to 100/i)).toBeInTheDocument()
})

test('VirusTotal verdict shows detections and links out', () => {
  mockHasRole.mockReturnValue(false)
  renderPage()
  const link = screen.getByRole('link', { name: '4/70' })
  expect(link).toHaveAttribute('href', 'https://www.virustotal.com/gui/ip-address/1.2.3.4')
  expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'))
})

test('analyst can enrich or refresh; viewer cannot', () => {
  mockHasRole.mockImplementation((r: string) => r === 'analyst')
  renderPage()
  fireEvent.click(screen.getByRole('button', { name: 'Refresh' })) // row 1 already has a verdict
  expect(enrichMutate).toHaveBeenCalledWith('1')
  fireEvent.click(screen.getByRole('button', { name: 'Enrich' })) // row 2 has none
  expect(enrichMutate).toHaveBeenLastCalledWith('2')
})

test('viewer sees no enrich buttons', () => {
  mockHasRole.mockReturnValue(false)
  renderPage()
  expect(screen.queryByRole('button', { name: /enrich|refresh/i })).not.toBeInTheDocument()
})
