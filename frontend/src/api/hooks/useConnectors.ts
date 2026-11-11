import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiDelete } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { ConnectorStatus } from '@/api/types'

const T = (tid: string) => `/api/v1/tenants/${tid}`

export function useConnectors(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['connectors', tenantId],
    queryFn: () => apiGet<ConnectorStatus[]>(`${T(tenantId)}/connectors`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}

export function useSetConnector(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ provider, url, apiKey }: { provider: string; url: string; apiKey: string }) => {
      const res = await fetch(`${T(tenantId)}/connectors/${provider}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${user?.access_token}` },
        body: JSON.stringify({ url, api_key: apiKey }),
      })
      const json = await res.json()
      if (!res.ok) throw new Error(json?.error?.message ?? `HTTP ${res.status}`)
      return json as ConnectorStatus
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['connectors', tenantId] }),
  })
}

export function useDeleteConnector(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (provider: string) =>
      apiDelete(`${T(tenantId)}/connectors/${provider}`, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['connectors', tenantId] }),
  })
}
