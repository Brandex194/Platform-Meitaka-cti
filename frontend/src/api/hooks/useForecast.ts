import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'

export interface ForecastResult {
  forecast: number[]
  message?: string
}

export function useForecast(tenantId: string, horizon = 7) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['ml-forecast', tenantId, horizon],
    queryFn: () =>
      apiGet<ForecastResult>(
        `/api/v1/ml/forecast?tenant_id=${encodeURIComponent(tenantId)}&horizon=${horizon}`,
        user?.access_token,
      ),
    enabled: !!user && !!tenantId,
  })
}
