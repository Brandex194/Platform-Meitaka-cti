import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'

const mockHasRole = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
}))

const createKey = vi.fn()
const revokeKey = vi.fn()
const createTenant = vi.fn()
const auditSpy = vi.fn()
const KEYS = [
  { id: 'k1', name: 'SIEM', prefix: 'mk_ab12cd34', created_by: null, created_at: '2026-11-09T10:00:00Z', expires_at: null, revoked_at: null, last_used_at: null, status: 'active' },
  { id: 'k2', name: 'Old', prefix: 'mk_ffff0000', created_by: null, created_at: '2026-11-01T10:00:00Z', expires_at: null, revoked_at: '2026-11-02T10:00:00Z', last_used_at: null, status: 'revoked' },
]
vi.mock('@/api/hooks/useManagement', () => ({
  useApiKeys: () => ({ data: { items: KEYS, total: 2 }, isLoading: false }),
  useCreateApiKey: () => ({ mutate: createKey, isPending: false, error: null }),
  useRevokeApiKey: () => ({ mutate: revokeKey, error: null }),
  useAuditLog: (...a: unknown[]) => {
    auditSpy(...a)
    return {
      data: { items: [{ id: 'a1', actor_id: '12345678-aaaa', action: 'POST /x/cases', resource_type: null, resource_id: null, ip: '10.0.0.1', status_code: 201, payload: null, created_at: '2026-11-09T10:00:00Z' }], total: 60, page: 1, size: 25 },
      isLoading: false,
    }
  },
  useTenants: () => ({ data: { items: [{ id: 't1', name: 'Acme', slug: 'acme', sector: null, created_at: '' }], total: 1 }, isLoading: false }),
  useCreateTenant: () => ({ mutate: createTenant, isPending: false, error: null }),
  useUpdateTenant: () => ({ mutate: vi.fn(), isPending: false, error: null }),
}))

const saveKey = vi.fn()
let vtConfigured = false
vi.mock('@/api/hooks/useIntegrations', () => ({
  useIntegrations: () => ({
    data: [{ provider: 'virustotal', label: 'VirusTotal', configured: vtConfigured, updated_at: vtConfigured ? '2026-11-09T10:00:00Z' : null }],
    isLoading: false,
  }),
  useSetIntegrationKey: () => ({ mutate: saveKey, reset: vi.fn(), isPending: false, error: null }),
  useDeleteIntegrationKey: () => ({ mutate: vi.fn(), error: null }),
}))

import { Management } from '@/pages/Management'

const show = () =>
  render(
    <MemoryRouter>
      <QueryClientProvider client={new QueryClient()}><Management tenantId="t1" /></QueryClientProvider>
    </MemoryRouter>,
  )

beforeEach(() => { vi.clearAllMocks(); vtConfigured = false })

test('non admins see no management', () => {
  mockHasRole.mockReturnValue(false)
  show()
  expect(screen.getByText(/tenant administrators only/i)).toBeInTheDocument()
  expect(screen.queryByRole('tab')).not.toBeInTheDocument()
})

test('tenant admin: keys listed, revoke offered only for live keys, no Tenants tab', () => {
  mockHasRole.mockImplementation((r: string) => r === 'tenant_admin')
  show()
  expect(screen.getByText('SIEM')).toBeInTheDocument()
  expect(screen.getAllByRole('button', { name: 'Revoke' })).toHaveLength(1)
  expect(screen.queryByRole('tab', { name: 'Tenants' })).not.toBeInTheDocument()
})

test('creating a key shows the full key once and sends name and days', () => {
  mockHasRole.mockImplementation((r: string) => r === 'tenant_admin')
  createKey.mockImplementation((_b, opts) => opts.onSuccess({ ...KEYS[0], key: 'mk_ab12cd34_SECRETVALUE' }))
  show()
  fireEvent.click(screen.getByRole('button', { name: 'New API key' }))
  fireEvent.change(screen.getByLabelText('Key name'), { target: { value: ' CI ' } })
  fireEvent.click(screen.getByRole('button', { name: 'Create' }))
  expect(createKey.mock.calls[0][0]).toEqual({ name: 'CI', expires_in_days: 90 })
  expect(screen.getByRole('dialog', { name: 'New API key created' })).toHaveTextContent('mk_ab12cd34_SECRETVALUE')
  fireEvent.click(screen.getByRole('button', { name: 'I have saved it' }))
  expect(screen.queryByText(/SECRETVALUE/)).not.toBeInTheDocument()
})

test('invalid days disables Create; empty days means never', () => {
  mockHasRole.mockImplementation((r: string) => r === 'tenant_admin')
  show()
  fireEvent.click(screen.getByRole('button', { name: 'New API key' }))
  fireEvent.change(screen.getByLabelText('Key name'), { target: { value: 'x' } })
  fireEvent.change(screen.getByLabelText('Expires in days'), { target: { value: '9999' } })
  expect(screen.getByRole('button', { name: 'Create' })).toBeDisabled()
  fireEvent.change(screen.getByLabelText('Expires in days'), { target: { value: '' } })
  expect(screen.getByRole('button', { name: 'Create' })).toBeEnabled()
})

test('revoke asks for confirmation', () => {
  mockHasRole.mockImplementation((r: string) => r === 'tenant_admin')
  show()
  fireEvent.click(screen.getByRole('button', { name: 'Revoke' }))
  fireEvent.click(screen.getByRole('button', { name: /confirm/i }))
  expect(revokeKey).toHaveBeenCalledWith('k1')
})

test('audit tab pages and filters', () => {
  mockHasRole.mockImplementation((r: string) => r === 'tenant_admin')
  show()
  fireEvent.click(screen.getByRole('tab', { name: 'Audit log' }))
  expect(screen.getByText('POST /x/cases')).toBeInTheDocument()
  expect(screen.getByText('Page 1 of 3')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(auditSpy).toHaveBeenLastCalledWith('t1', 2, '')
  fireEvent.change(screen.getByLabelText('Filter actions'), { target: { value: 'cases' } })
  expect(auditSpy).toHaveBeenLastCalledWith('t1', 1, 'cases') // filter goes back to page 1
})

test('super admin sees tenants and can create one', () => {
  mockHasRole.mockImplementation((r: string) => r === 'super_admin')
  show()
  fireEvent.click(screen.getByRole('tab', { name: 'Tenants' }))
  expect(screen.getByText('Acme')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'New tenant' }))
  fireEvent.change(screen.getByLabelText('Tenant name'), { target: { value: 'Beta' } })
  fireEvent.change(screen.getByLabelText('Tenant slug'), { target: { value: 'beta' } })
  fireEvent.click(screen.getByRole('button', { name: 'Create' }))
  expect(createTenant.mock.calls[0][0]).toEqual({ name: 'Beta', slug: 'beta', sector: undefined })
})

test('roles tab lists every role', () => {
  mockHasRole.mockImplementation((r: string) => r === 'tenant_admin')
  show()
  fireEvent.click(screen.getByRole('tab', { name: 'Roles' }))
  for (const r of ['super_admin', 'tenant_admin', 'analyst', 'viewer', 'api_user'])
    expect(screen.getByText(r)).toBeInTheDocument()
})

test('integration key field is a password input and never shows a stored key', () => {
  mockHasRole.mockImplementation((r: string) => r === 'tenant_admin')
  vtConfigured = true
  show()
  fireEvent.click(screen.getByRole('tab', { name: 'Integrations' }))
  expect(screen.getByText(/Key configured/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Replace key' }))
  const input = screen.getByLabelText('API key') as HTMLInputElement
  expect(input.type).toBe('password')
  expect(input.value).toBe('') // nothing prefilled: the page never receives the key
  expect(input).toHaveAttribute('autocomplete', 'off')
})

test('saving sends the trimmed key and the dialog closes clearing it', () => {
  mockHasRole.mockImplementation((r: string) => r === 'tenant_admin')
  saveKey.mockImplementation((_v, opts) => opts.onSuccess())
  show()
  fireEvent.click(screen.getByRole('tab', { name: 'Integrations' }))
  expect(screen.getByText('No key configured')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Add key' }))
  fireEvent.change(screen.getByLabelText('API key'), { target: { value: '  abc123  ' } })
  fireEvent.click(screen.getByRole('button', { name: 'Save key' }))
  expect(saveKey.mock.calls[0][0]).toEqual({ provider: 'virustotal', apiKey: 'abc123' })
  expect(screen.queryByLabelText('API key')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Add key' }))
  expect((screen.getByLabelText('API key') as HTMLInputElement).value).toBe('')
})
