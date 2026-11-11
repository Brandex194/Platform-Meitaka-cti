import { useQuery } from '@tanstack/react-query'
import { apiGet } from '@/api/client'
import { useAuthStore } from '@/auth/store'

export interface SimilarIoc {
  value: string
  score: number
}

export interface SimilarIocsResult {
  results: SimilarIoc[]
  message?: string
}

export function useSimilarIocs(value: string, k = 10) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['ml-similar-iocs', value, k],
    queryFn: () =>
      apiGet<SimilarIocsResult>(
        `/api/v1/ml/similar-iocs?value=${encodeURIComponent(value)}&k=${k}`,
        user?.access_token,
      ),
    enabled: !!user && !!value,
  })
}
