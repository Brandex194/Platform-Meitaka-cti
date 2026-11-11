import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPost, apiPatch, apiDelete } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Campaign } from '@/api/types'

export function useCampaigns() {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['campaigns'],
    queryFn: () => apiGet<Paginated<Campaign>>('/api/v1/campaigns', user?.access_token),
    enabled: !!user,
  })
}

export interface CampaignBody {
  name?: string
  threat_actor_id?: string | null
  description?: string | null
}

const BASE = (tid: string) => `/api/v1/tenants/${tid}/campaigns`

export function useCreateCampaign(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: CampaignBody) => apiPost<Campaign>(BASE(tenantId), body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['campaigns'] }),
  })
}

export function useUpdateCampaign(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string } & CampaignBody) =>
      apiPatch<Campaign>(`${BASE(tenantId)}/${id}`, body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['campaigns'] }),
  })
}

export function useDeleteCampaign(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiDelete(`${BASE(tenantId)}/${id}`, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['campaigns'] }),
  })
}
