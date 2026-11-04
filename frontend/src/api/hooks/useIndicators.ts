import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Indicator } from '@/api/types'

export function useIndicators(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['indicators', tenantId],
    queryFn: () =>
      apiGet<Paginated<Indicator>>(`/api/v1/indicators?tenant_id=${tenantId}`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}
