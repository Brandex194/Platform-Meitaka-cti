import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPatch } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, ExposureMatch } from '@/api/types'

export function useExposure(tenantId: string, page = 1, size = 50) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['exposure', tenantId, page],
    queryFn: () =>
      apiGet<Paginated<ExposureMatch>>(
        `/api/v1/tenants/${tenantId}/exposure-matches?page=${page}&size=${size}`,
        user?.access_token,
      ),
    enabled: !!user && !!tenantId,
  })
}

export function usePatchExposure(tenantId: string) {
  const { user } = useAuthStore()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiPatch(`/api/v1/exposure-matches/${id}`, { status }, user?.access_token),
    onMutate: async ({ id, status }) => {
      await queryClient.cancelQueries({ queryKey: ['exposure', tenantId] })
      const prev = queryClient.getQueryData(['exposure', tenantId, 1])
      queryClient.setQueryData(
        ['exposure', tenantId, 1],
        (old: Paginated<ExposureMatch> | undefined) =>
          old
            ? { ...old, items: old.items.map((e) => (e.id === id ? { ...e, status } : e)) }
            : old,
      )
      return { prev }
    },
    onError: (_err, _vars, ctx) => {
      queryClient.setQueryData(['exposure', tenantId, 1], ctx?.prev)
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['exposure', tenantId] }),
  })
}
