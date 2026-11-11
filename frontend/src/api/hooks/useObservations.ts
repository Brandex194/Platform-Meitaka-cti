import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Observation } from '@/api/types'

export function useObservations(tenantId: string, eventType?: string) {
  const { user } = useAuthStore()
  const qs = eventType ? `?event_type=${encodeURIComponent(eventType)}` : ''
  return useQuery({
    queryKey: ['observations', tenantId, eventType],
    queryFn: () =>
      apiGet<Paginated<Observation>>(`/api/v1/tenants/${tenantId}/observations${qs}`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}
