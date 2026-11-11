import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPost, apiDelete } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Integration, Enrichment, Paginated } from '@/api/types'

const T = (tid: string) => `/api/v1/tenants/${tid}`

export function useIntegrations(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['integrations', tenantId],
    queryFn: () => apiGet<Integration[]>(`${T(tenantId)}/integrations`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}

/** Store or replace a key. The server never sends it back; the form clears itself after this. */
export function useSetIntegrationKey(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ provider, apiKey }: { provider: string; apiKey: string }) => {
      // PUT through fetch: client.ts has no put helper, and the body must not be logged or kept.
      const res = await fetch(`${T(tenantId)}/integrations/${provider}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${user?.access_token}` },
        body: JSON.stringify({ api_key: apiKey }),
      })
      const json = await res.json()
      if (!res.ok) throw new Error(json?.error?.message ?? `HTTP ${res.status}`)
      return json as Integration
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['integrations', tenantId] }),
  })
}

export function useDeleteIntegrationKey(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (provider: string) =>
      apiDelete(`${T(tenantId)}/integrations/${provider}`, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['integrations', tenantId] }),
  })
}

export function useEnrichments(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['enrichments', tenantId],
    queryFn: () =>
      apiGet<Paginated<Enrichment>>(`${T(tenantId)}/enrichments?size=200`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}

export function useEnrichIndicator(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (indicatorId: string) =>
      apiPost<Enrichment>(`${T(tenantId)}/indicators/${indicatorId}/enrich`, {}, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['enrichments', tenantId] }),
  })
}
