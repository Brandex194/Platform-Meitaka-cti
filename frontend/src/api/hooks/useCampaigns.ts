import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Campaign } from '@/api/types'

export function useCampaigns() {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['campaigns'],
    queryFn: () => apiGet<Paginated<Campaign>>('/api/v1/campaigns', user?.access_token),
    enabled: !!user,
  })
}
