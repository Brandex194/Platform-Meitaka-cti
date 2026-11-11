import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Score, ScoreExplanation } from '@/api/types'

export function useScores(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['scores', tenantId],
    queryFn: () =>
      apiGet<Paginated<Score>>(`/api/v1/tenants/${tenantId}/scores`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}

export function useScoreExplanation(tenantId: string, assetId: string | null) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['score-explanation', tenantId, assetId],
    queryFn: () =>
      apiGet<ScoreExplanation>(
        `/api/v1/tenants/${tenantId}/assets/${assetId}/score-explanation`,
        user?.access_token,
      ),
    enabled: !!user && !!tenantId && !!assetId,
  })
}
