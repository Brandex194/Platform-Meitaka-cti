import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPost, apiPatch, apiDelete } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, ApiKey, ApiKeyCreated, AuditEntry, TenantInfo } from '@/api/types'

const T = (tid: string) => `/api/v1/tenants/${tid}`

export function useApiKeys(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['api-keys', tenantId],
    queryFn: () => apiGet<Paginated<ApiKey>>(`${T(tenantId)}/api-keys`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}

export function useCreateApiKey(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { name: string; expires_in_days?: number }) =>
      apiPost<ApiKeyCreated>(`${T(tenantId)}/api-keys`, body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys', tenantId] }),
  })
}

export function useRevokeApiKey(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiDelete(`${T(tenantId)}/api-keys/${id}`, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys', tenantId] }),
  })
}

export function useAuditLog(tenantId: string, page: number, q: string) {
  const { user } = useAuthStore()
  const qs = new URLSearchParams({ page: String(page), size: '25' })
  if (q.trim()) qs.set('q', q.trim())
  return useQuery({
    queryKey: ['audit', tenantId, page, q.trim()],
    queryFn: () =>
      apiGet<Paginated<AuditEntry>>(`${T(tenantId)}/audit-logs?${qs}`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}

export function useTenants(enabled: boolean) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['admin-tenants'],
    queryFn: () => apiGet<Paginated<TenantInfo>>('/api/v1/admin/tenants?size=200', user?.access_token),
    enabled: !!user && enabled,
  })
}

export function useCreateTenant() {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { name: string; slug: string; sector?: string }) =>
      apiPost<TenantInfo>('/api/v1/admin/tenants', body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-tenants'] }),
  })
}

export function useUpdateTenant() {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string; name?: string; sector?: string | null }) =>
      apiPatch<TenantInfo>(`/api/v1/admin/tenants/${id}`, body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-tenants'] }),
  })
}
