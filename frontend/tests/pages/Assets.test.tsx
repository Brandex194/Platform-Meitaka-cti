import { render, screen, fireEvent } from '@testing-library/react'
import { vi } from 'vitest'

const mockHasRole = vi.fn()
const mutate = vi.fn()
vi.mock('@/auth/store', () => ({
  useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
}))
vi.mock('@/api/hooks/useAssets', () => ({
  useAssets: () => ({
    data: {
      items: [{ id: 'a1', tenant_id: 't1', hostname: 'web01', ip: null, exposure: 'internet', impact: null, created_at: '' }],
      total: 1, page: 1, size: 50,
    },
    isLoading: false,
  }),
  usePatchAsset: () => ({ mutate, isPending: false }),
}))

import { Assets } from '@/pages/Assets'

beforeEach(() => mutate.mockReset())

test('shows the asset context and saves a change', () => {
  mockHasRole.mockImplementation((r: string) => r === 'tenant_admin')
  render(<Assets tenantId="t1" />)
  expect(screen.getByLabelText('Esposizione di web01')).toHaveValue('internet')
  expect(screen.getByLabelText('Impatto di web01')).toHaveValue('')
  fireEvent.change(screen.getByLabelText('Impatto di web01'), { target: { value: 'business' } })
  expect(mutate).toHaveBeenCalledWith({ id: 'a1', impact: 'business' })
})

test('viewer sees the context but cannot change it', () => {
  mockHasRole.mockReturnValue(false)
  render(<Assets tenantId="t1" />)
  expect(screen.getByLabelText('Esposizione di web01')).toBeDisabled()
})
