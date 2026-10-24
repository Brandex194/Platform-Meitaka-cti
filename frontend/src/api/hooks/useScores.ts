import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Score } from '@/api/types'

export function useScores(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['scores', tenantId],
    queryFn: () =>
      apiGet<Paginated<Score>>(`/api/v1/tenants/${tenantId}/scores`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}
