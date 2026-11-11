import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiPost } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { StixImportResult } from '@/api/types'

const BASE = (tid: string) => `/api/v1/tenants/${tid}/stix`

/** Send an already parsed bundle. New indicators, actors and campaigns refresh their lists. */
export function useImportStix(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (bundle: unknown) =>
      apiPost<StixImportResult>(`${BASE(tenantId)}/import`, bundle, user?.access_token),
    onSuccess: () => {
      for (const key of ['indicators', 'threat-actors', 'actors', 'campaigns'])
        qc.invalidateQueries({ queryKey: [key] })
    },
  })
}

/** Download the bundle as a file. The browser cannot add the token to a plain link, so fetch it. */
export async function downloadStix(tenantId: string, token: string | undefined, ownOnly: boolean) {
  const res = await fetch(`${BASE(tenantId)}/export${ownOnly ? '?own_only=true' : ''}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) {
    let message = `HTTP ${res.status}`
    try {
      message = (await res.json())?.error?.message ?? message
    } catch {
      /* body was not JSON */
    }
    throw new Error(message)
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'meitaka-stix-bundle.json'
  a.click()
  URL.revokeObjectURL(url)
}
