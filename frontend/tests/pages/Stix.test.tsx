import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'

const mockHasRole = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
}))

const importMutate = vi.fn()
const importReset = vi.fn()
let importState: Record<string, unknown> = {}
const download = vi.fn()
vi.mock('@/api/hooks/useStix', () => ({
  useImportStix: () => ({ mutate: importMutate, reset: importReset, isPending: false, error: null, data: undefined, ...importState }),
  downloadStix: (...a: unknown[]) => download(...a),
}))

import { Stix } from '@/pages/Stix'

const show = () =>
  render(<QueryClientProvider client={new QueryClient()}><Stix tenantId="t1" /></QueryClientProvider>)

const file = (text: string, name = 'b.json') => new File([text], name, { type: 'application/json' })
const pick = (f: File) => fireEvent.change(screen.getByLabelText('STIX bundle file'), { target: { files: [f] } })

beforeEach(() => {
  vi.clearAllMocks()
  importState = {}
  mockHasRole.mockImplementation((r: string) => r === 'analyst')
  download.mockResolvedValue(undefined)
})

test('viewer gets a message, not the tools', () => {
  mockHasRole.mockReturnValue(false)
  show()
  expect(screen.getByText(/analysts and administrators/i)).toBeInTheDocument()
  expect(screen.queryByLabelText('STIX bundle file')).not.toBeInTheDocument()
})

test('export passes the own-only choice', () => {
  show()
  fireEvent.click(screen.getByRole('button', { name: 'Download bundle' }))
  expect(download).toHaveBeenLastCalledWith('t1', 'tok', false)
  fireEvent.click(screen.getByRole('checkbox'))
  fireEvent.click(screen.getByRole('button', { name: 'Download bundle' }))
  expect(download).toHaveBeenLastCalledWith('t1', 'tok', true)
})

test('export failure is shown', async () => {
  download.mockRejectedValue(new Error('Insufficient permissions'))
  show()
  fireEvent.click(screen.getByRole('button', { name: 'Download bundle' }))
  expect(await screen.findByText(/Insufficient permissions/)).toBeInTheDocument()
})

test('a valid file is parsed and sent as an object', async () => {
  show()
  pick(file('{"type":"bundle","objects":[]}'))
  await waitFor(() => expect(importMutate).toHaveBeenCalled())
  expect(importMutate.mock.calls[0][0]).toEqual({ type: 'bundle', objects: [] })
})

test('a file that is not JSON is refused before sending', async () => {
  show()
  pick(file('this is not json'))
  expect(await screen.findByText(/not valid JSON/)).toBeInTheDocument()
  expect(importMutate).not.toHaveBeenCalled()
})

test('result table shows counts and skipped reasons', () => {
  importState = {
    data: {
      created: { indicators: 3, threat_actors: 1, campaigns: 0, links: 2 },
      duplicates: { indicators: 2, threat_actors: 0, campaigns: 1, links: 0 },
      skipped_total: 2,
      skipped: [{ id: 'malware--1', type: 'malware', reason: "type 'malware' is not supported yet" }],
    },
  }
  show()
  const result = screen.getByLabelText('Import result')
  expect(result).toHaveTextContent('Created')
  expect(result).toHaveTextContent("type 'malware' is not supported yet")
  expect(result).toHaveTextContent('2 objects not imported (first 1 shown)')
})
