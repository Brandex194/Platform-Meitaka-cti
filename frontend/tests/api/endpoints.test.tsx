// Contract test: every data hook must call the tenant-scoped path the backend exposes.
// The list of paths mirrors backend/app/api/v1/routes; if a route moves, update both.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'

const apiGet = vi.fn()
const apiPatch = vi.fn()
const apiPost = vi.fn()
const apiDelete = vi.fn()
vi.mock('@/api/client', () => ({
  apiGet: (...a: unknown[]) => apiGet(...a),
  apiPatch: (...a: unknown[]) => apiPatch(...a),
  apiPost: (...a: unknown[]) => apiPost(...a),
  apiDelete: (...a: unknown[]) => apiDelete(...a),
}))
vi.mock('@/auth/store', () => ({ useAuthStore: () => ({ user: { access_token: 'tok' } }) }))

import { useAssets, usePatchAsset } from '@/api/hooks/useAssets'
import { useScores } from '@/api/hooks/useScores'
import { useDashboard } from '@/api/hooks/useDashboard'
import { useExposure, usePatchExposure } from '@/api/hooks/useExposure'
import { useIndicators, useCreateIndicator, useDeleteIndicator } from '@/api/hooks/useIndicators'
import { useObservations } from '@/api/hooks/useObservations'
import { useQuickReport } from '@/api/hooks/useReports'
import { useCases } from '@/api/hooks/useCases'
import { useActors, useCreateActor, useUpdateActor, useDeleteActor } from '@/api/hooks/useActors'
import { useCampaigns, useCreateCampaign, useUpdateCampaign, useDeleteCampaign } from '@/api/hooks/useCampaigns'
import { useCorrelationEvents } from '@/api/hooks/useAnalysis'
import { useForecast } from '@/api/hooks/useForecast'
import { useSimilarIocs } from '@/api/hooks/useSimilarIocs'

const T = 'tid'
const wrapper = ({ children }: { children: ReactNode }) => (
  <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    {children}
  </QueryClientProvider>
)

beforeEach(() => {
  apiGet.mockReset().mockResolvedValue({ items: [], total: 0, page: 1, size: 50 })
  apiPatch.mockReset().mockResolvedValue({})
  apiPost.mockReset().mockResolvedValue({})
  apiDelete.mockReset().mockResolvedValue(undefined)
})

const cases: [string, () => unknown, string][] = [
  ['assets', () => useAssets(T), `/api/v1/tenants/${T}/assets?page=1&size=50`],
  ['scores', () => useScores(T), `/api/v1/tenants/${T}/scores`],
  ['dashboard', () => useDashboard(T), `/api/v1/tenants/${T}/dashboard`],
  ['exposure', () => useExposure(T), `/api/v1/tenants/${T}/exposure-matches?page=1&size=50`],
  ['indicators', () => useIndicators(T), `/api/v1/tenants/${T}/indicators`],
  ['observations', () => useObservations(T, 'darkweb'), `/api/v1/tenants/${T}/observations?event_type=darkweb`],
  ['reports', () => useQuickReport(T), `/api/v1/tenants/${T}/reports/quick`],
  ['cases', () => useCases(T), `/api/v1/tenants/${T}/cases`],
  ['correlation events', () => useCorrelationEvents(T), `/api/v1/tenants/${T}/correlation-events`],
  ['threat actors', () => useActors(), '/api/v1/threat-actors'],
  ['campaigns', () => useCampaigns(), '/api/v1/campaigns'],
  ['ml forecast', () => useForecast(T), `/api/v1/ml/forecast?tenant_id=${T}&horizon=7`],
  ['ml similar iocs', () => useSimilarIocs('1.2.3.4'), '/api/v1/ml/similar-iocs?value=1.2.3.4&k=10'],
]

describe('API paths', () => {
  it.each(cases)('%s', async (_name, hook, path) => {
    renderHook(hook, { wrapper })
    await waitFor(() => expect(apiGet).toHaveBeenCalled())
    expect(apiGet.mock.calls[0][0]).toBe(path)
  })

  it('exposure status update is tenant-scoped', async () => {
    const { result } = renderHook(() => usePatchExposure(T), { wrapper })
    result.current.mutate({ id: 'e1', status: 'resolved' })
    await waitFor(() => expect(apiPatch).toHaveBeenCalled())
    expect(apiPatch.mock.calls[0][0]).toBe(`/api/v1/tenants/${T}/exposure-matches/e1`)
  })

  it('asset context update is tenant-scoped', async () => {
    const { result } = renderHook(() => usePatchAsset(T), { wrapper })
    result.current.mutate({ id: 'a1', exposure: 'dmz' })
    await waitFor(() => expect(apiPatch).toHaveBeenCalled())
    expect(apiPatch.mock.calls[0][0]).toBe(`/api/v1/tenants/${T}/assets/a1`)
    expect(apiPatch.mock.calls[0][1]).toEqual({ exposure: 'dmz' })
  })

  it('actor writes go to the tenant-scoped path', async () => {
    const create = renderHook(() => useCreateActor(T), { wrapper })
    create.result.current.mutate({ name: 'FIN7' })
    await waitFor(() => expect(apiPost).toHaveBeenCalled())
    expect(apiPost.mock.calls[0][0]).toBe(`/api/v1/tenants/${T}/threat-actors`)

    const update = renderHook(() => useUpdateActor(T), { wrapper })
    update.result.current.mutate({ id: 'a1', description: 'x' })
    await waitFor(() => expect(apiPatch).toHaveBeenCalled())
    expect(apiPatch.mock.calls[0][0]).toBe(`/api/v1/tenants/${T}/threat-actors/a1`)
    expect(apiPatch.mock.calls[0][1]).toEqual({ description: 'x' })

    const del = renderHook(() => useDeleteActor(T), { wrapper })
    del.result.current.mutate('a1')
    await waitFor(() => expect(apiDelete).toHaveBeenCalled())
    expect(apiDelete.mock.calls[0][0]).toBe(`/api/v1/tenants/${T}/threat-actors/a1`)
  })

  it('campaign writes go to the tenant-scoped path', async () => {
    const create = renderHook(() => useCreateCampaign(T), { wrapper })
    create.result.current.mutate({ name: 'Op X', threat_actor_id: null })
    await waitFor(() => expect(apiPost).toHaveBeenCalled())
    expect(apiPost.mock.calls[0][0]).toBe(`/api/v1/tenants/${T}/campaigns`)

    const update = renderHook(() => useUpdateCampaign(T), { wrapper })
    update.result.current.mutate({ id: 'c1', name: 'y' })
    await waitFor(() => expect(apiPatch).toHaveBeenCalled())
    expect(apiPatch.mock.calls[0][0]).toBe(`/api/v1/tenants/${T}/campaigns/c1`)

    const del = renderHook(() => useDeleteCampaign(T), { wrapper })
    del.result.current.mutate('c1')
    await waitFor(() => expect(apiDelete).toHaveBeenCalled())
    expect(apiDelete.mock.calls[0][0]).toBe(`/api/v1/tenants/${T}/campaigns/c1`)
  })

  it('indicator writes go to the tenant-scoped path', async () => {
    const create = renderHook(() => useCreateIndicator(T), { wrapper })
    create.result.current.mutate({ ioc_type: 'ip', value: '1.2.3.4', confidence: null })
    await waitFor(() => expect(apiPost).toHaveBeenCalled())
    expect(apiPost.mock.calls[0][0]).toBe(`/api/v1/tenants/${T}/indicators`)

    const del = renderHook(() => useDeleteIndicator(T), { wrapper })
    del.result.current.mutate('i1')
    await waitFor(() => expect(apiDelete).toHaveBeenCalled())
    expect(apiDelete.mock.calls[0][0]).toBe(`/api/v1/tenants/${T}/indicators/i1`)
  })
})
