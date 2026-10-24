import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, CorrelationEvent } from '@/api/types'

export function useCorrelationEvents(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['correlation-events', tenantId],
    queryFn: () =>
      apiGet<Paginated<CorrelationEvent>>(
        `/api/v1/tenants/${tenantId}/correlation-events`,
        user?.access_token,
      ),
    enabled: !!user && !!tenantId,
  })
}
