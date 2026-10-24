import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Asset } from '@/api/types'

export function useAssets(tenantId: string, page = 1, size = 50) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['assets', tenantId, page],
    queryFn: () =>
      apiGet<Paginated<Asset>>(
        `/api/v1/tenants/${tenantId}/assets?page=${page}&size=${size}`,
        user?.access_token,
      ),
    enabled: !!user && !!tenantId,
  })
}
