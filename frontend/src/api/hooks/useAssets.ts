import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPatch } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Asset, AssetExposure, AssetImpact } from '@/api/types'

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

export type AssetContextPatch = { exposure?: AssetExposure | null; impact?: AssetImpact | null }

/** Architettura §5.2 context; counts from the next score computation. */
export function usePatchAsset(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string } & AssetContextPatch) =>
      apiPatch<Asset>(`/api/v1/tenants/${tenantId}/assets/${id}`, body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets', tenantId] }),
  })
}
