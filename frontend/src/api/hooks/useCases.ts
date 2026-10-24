import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPost, apiPatch, apiDelete } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Case } from '@/api/types'

const BASE = (tid: string) => `/api/v1/tenants/${tid}/cases`

export function useCases(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['cases', tenantId],
    queryFn: () => apiGet<Paginated<Case>>(BASE(tenantId), user?.access_token),
    enabled: !!user && !!tenantId,
  })
}

export function useCreateCase(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { title: string; description?: string; severity: string }) =>
      apiPost<Case>(BASE(tenantId), body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cases', tenantId] }),
  })
}

export function useUpdateCase(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string; title?: string; status?: string; severity?: string }) =>
      apiPatch<Case>(`${BASE(tenantId)}/${id}`, body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cases', tenantId] }),
  })
}

export function useDeleteCase(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiDelete(`${BASE(tenantId)}/${id}`, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cases', tenantId] }),
  })
}
