import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

import { apiGet, apiPost } from '@/api/client'

beforeEach(() => mockFetch.mockReset())

describe('apiGet', () => {
  it('sets Authorization Bearer header when token provided', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, json: async () => [] })
    await apiGet('/api/v1/assets', 'tok123')
    const [, init] = mockFetch.mock.calls[0]
    expect((init as RequestInit).headers!['Authorization']).toBe('Bearer tok123')
  })

  it('omits Authorization header when no token', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, json: async () => [] })
    await apiGet('/api/v1/assets')
    const [, init] = mockFetch.mock.calls[0]
    expect((init as RequestInit).headers!['Authorization']).toBeUndefined()
  })

  it('throws with error.message on non-ok response', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      json: async () => ({ error: { code: 'NOT_FOUND', message: 'not found', detail: {} } }),
    })
    await expect(apiGet('/api/v1/assets')).rejects.toThrow('not found')
  })

  it('throws generic message when error envelope missing', async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 500, json: async () => ({}) })
    await expect(apiGet('/api/v1/assets')).rejects.toThrow('HTTP 500')
  })
})

describe('apiPost', () => {
  it('sends JSON body', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({ id: '1' }) })
    await apiPost('/api/v1/cases', { title: 'Test' }, 'tok')
    const [, init] = mockFetch.mock.calls[0]
    expect((init as RequestInit).body).toBe(JSON.stringify({ title: 'Test' }))
  })
})
