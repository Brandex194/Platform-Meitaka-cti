import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPost, apiPatch, apiDelete } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Observation, Leak } from '@/api/types'

const BASE = (tid: string) => `/api/v1/tenants/${tid}/darkweb`

export type DarkWebLeak = Omit<Leak, 'tenant_id'>

export function useLeaks(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['darkweb-leaks', tenantId],
    queryFn: () => apiGet<Paginated<DarkWebLeak>>(`${BASE(tenantId)}/leaks`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}

function useInvalidating<V>(tenantId: string, key: string, fn: (v: V, token?: string) => Promise<unknown>) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: V) => fn(v, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: [key, tenantId] }),
  })
}

export const useCreateFinding = (t: string) =>
  useInvalidating(t, 'observations', (b: { source: string; context: string; severity: string }, tok) =>
    apiPost<Observation>(`${BASE(t)}/findings`, b, tok))

export const useSetFindingStatus = (t: string) =>
  useInvalidating(t, 'observations', (v: { id: string; status: string }, tok) =>
    apiPatch<Observation>(`${BASE(t)}/findings/${v.id}`, { status: v.status }, tok))

export const useDeleteFinding = (t: string) =>
  useInvalidating(t, 'observations', (id: string, tok) => apiDelete(`${BASE(t)}/findings/${id}`, tok))

export const useCreateLeak = (t: string) =>
  useInvalidating(t, 'darkweb-leaks', (b: { email: string; breach_name: string; pwn_count?: number }, tok) =>
    apiPost<DarkWebLeak>(`${BASE(t)}/leaks`, b, tok))

export const useDeleteLeak = (t: string) =>
  useInvalidating(t, 'darkweb-leaks', (id: string, tok) => apiDelete(`${BASE(t)}/leaks/${id}`, tok))
