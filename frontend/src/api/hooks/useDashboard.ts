import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { DashboardData } from '@/api/types'

export function useDashboard(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['dashboard', tenantId],
    queryFn: () =>
      apiGet<DashboardData>(`/api/v1/tenants/${tenantId}/dashboard`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}
