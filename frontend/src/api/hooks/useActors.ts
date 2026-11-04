import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, ThreatActor } from '@/api/types'

export function useActors() {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['actors'],
    queryFn: () => apiGet<Paginated<ThreatActor>>('/api/v1/threat-actors', user?.access_token),
    enabled: !!user,
  })
}
