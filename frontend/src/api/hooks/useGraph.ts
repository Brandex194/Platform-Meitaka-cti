import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPost, apiDelete } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Indicator, KnowledgeGraph, Paginated } from '@/api/types'

const T = (tid: string) => `/api/v1/tenants/${tid}`

export function useGraph(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['graph', tenantId],
    queryFn: () => apiGet<KnowledgeGraph>(`${T(tenantId)}/graph`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}

/** Indicators the tenant can link (its own and the shared ones), newest first, up to 200. */
export function useLinkableIndicators(tenantId: string, enabled: boolean) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['indicators', tenantId, 'linkable'],
    queryFn: () =>
      apiGet<Paginated<Indicator>>(`${T(tenantId)}/indicators?size=200`, user?.access_token),
    enabled: !!user && !!tenantId && enabled,
  })
}

export function useLinkIndicator(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ campaignId, indicatorId }: { campaignId: string; indicatorId: string }) =>
      apiPost(`${T(tenantId)}/campaigns/${campaignId}/indicators`, { indicator_id: indicatorId }, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['graph', tenantId] }),
  })
}

export function useUnlinkIndicator(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ campaignId, indicatorId }: { campaignId: string; indicatorId: string }) =>
      apiDelete(`${T(tenantId)}/campaigns/${campaignId}/indicators/${indicatorId}`, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['graph', tenantId] }),
  })
}
