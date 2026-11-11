import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPost, apiDelete } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Indicator } from '@/api/types'

export function useIndicators(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['indicators', tenantId],
    queryFn: () =>
      apiGet<Paginated<Indicator>>(`/api/v1/tenants/${tenantId}/indicators`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}

export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'email'

export function useCreateIndicator(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { ioc_type: IndicatorType; value: string; confidence?: number | null }) =>
      apiPost<Indicator>(`/api/v1/tenants/${tenantId}/indicators`, body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['indicators', tenantId] }),
  })
}

export function useDeleteIndicator(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) =>
      apiDelete(`/api/v1/tenants/${tenantId}/indicators/${id}`, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['indicators', tenantId] }),
  })
}
