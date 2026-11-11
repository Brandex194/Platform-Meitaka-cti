import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { QuickReport } from '@/api/types'

export function useQuickReport(tenantId: string) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['reports', 'quick', tenantId],
    queryFn: () =>
      apiGet<QuickReport>(`/api/v1/tenants/${tenantId}/reports/quick`, user?.access_token),
    enabled: !!user && !!tenantId,
  })
}
