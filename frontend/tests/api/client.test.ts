import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

import { apiGet, apiPost, apiDelete } from '@/api/client'

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

describe('apiDelete', () => {
  it('resolves on 204 without trying to parse an empty body', async () => {
    const json = vi.fn().mockRejectedValue(new SyntaxError('Unexpected end of JSON input'))
    mockFetch.mockResolvedValueOnce({ ok: true, status: 204, json })
    await expect(apiDelete('/api/v1/tenants/t/cases/1', 'tok')).resolves.toBeUndefined()
    expect(json).not.toHaveBeenCalled()
  })

  it('still throws the API message when the delete is refused', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      json: async () => ({ error: { code: 'NOT_FOUND', message: 'Case not found', detail: {} } }),
    })
    await expect(apiDelete('/api/v1/tenants/t/cases/1', 'tok')).rejects.toThrow('Case not found')
  })
})
