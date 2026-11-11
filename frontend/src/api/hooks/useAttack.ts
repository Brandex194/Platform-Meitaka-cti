import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { AttackTechnique } from '@/api/types'

export function useAttackTechniques() {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['attack', 'techniques'],
    queryFn: () => apiGet<AttackTechnique[]>('/api/v1/attack/techniques', user?.access_token),
    enabled: !!user,
    staleTime: 1000 * 60 * 60, // catalog changes rarely
  })
}
