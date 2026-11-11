import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPost, apiPatch, apiDelete } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, ThreatActor } from '@/api/types'

export function useActors() {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['actors'],
    queryFn: () => apiGet<Paginated<ThreatActor>>('/api/v1/threat-actors', user?.access_token),
    enabled: !!user,
  })
}

export interface ActorBody {
  name?: string
  aliases?: string[] | null
  description?: string | null
}

const BASE = (tid: string) => `/api/v1/tenants/${tid}/threat-actors`

export function useCreateActor(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: ActorBody) => apiPost<ThreatActor>(BASE(tenantId), body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['actors'] }),
  })
}

export function useUpdateActor(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string } & ActorBody) =>
      apiPatch<ThreatActor>(`${BASE(tenantId)}/${id}`, body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['actors'] }),
  })
}

export function useDeleteActor(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiDelete(`${BASE(tenantId)}/${id}`, user?.access_token),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['actors'] })
      qc.invalidateQueries({ queryKey: ['campaigns'] }) // its campaigns lose the link
    },
  })
}
