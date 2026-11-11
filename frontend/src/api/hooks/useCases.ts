import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiGet, apiPost, apiPatch, apiDelete } from '@/api/client'
import { useAuthStore } from '@/auth/store'
import type { Paginated, Case, CaseNote, CaseEvent } from '@/api/types'

const BASE = (tid: string) => `/api/v1/tenants/${tid}/cases`

export function useCases(tenantId: string, status = '') {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['cases', tenantId, status],
    queryFn: () =>
      apiGet<Paginated<Case>>(
        status ? `${BASE(tenantId)}?status=${encodeURIComponent(status)}` : BASE(tenantId),
        user?.access_token,
      ),
    enabled: !!user && !!tenantId,
  })
}

export function useCreateCase(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { title: string; description?: string; severity: string }) =>
      apiPost<Case>(BASE(tenantId), body, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cases', tenantId] }),
  })
}

export function useUpdateCase(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      ...body
    }: {
      id: string
      title?: string
      description?: string
      status?: string
      severity?: string
    }) => apiPatch<Case>(`${BASE(tenantId)}/${id}`, body, user?.access_token),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ['cases', tenantId] })
      qc.invalidateQueries({ queryKey: ['case-timeline', tenantId, vars.id] })
    },
  })
}

export function useDeleteCase(tenantId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiDelete(`${BASE(tenantId)}/${id}`, user?.access_token),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cases', tenantId] }),
  })
}

export function useCaseNotes(tenantId: string, caseId: string | null) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['case-notes', tenantId, caseId],
    queryFn: () =>
      apiGet<Paginated<CaseNote>>(`${BASE(tenantId)}/${caseId}/notes`, user?.access_token),
    enabled: !!user && !!tenantId && !!caseId,
  })
}

export function useCaseTimeline(tenantId: string, caseId: string | null) {
  const { user } = useAuthStore()
  return useQuery({
    queryKey: ['case-timeline', tenantId, caseId],
    queryFn: () =>
      apiGet<Paginated<CaseEvent>>(`${BASE(tenantId)}/${caseId}/timeline`, user?.access_token),
    enabled: !!user && !!tenantId && !!caseId,
  })
}

export function useAddNote(tenantId: string, caseId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: string) =>
      apiPost<CaseNote>(`${BASE(tenantId)}/${caseId}/notes`, { body }, user?.access_token),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['case-notes', tenantId, caseId] })
      qc.invalidateQueries({ queryKey: ['case-timeline', tenantId, caseId] })
    },
  })
}

export function useDeleteNote(tenantId: string, caseId: string) {
  const { user } = useAuthStore()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (noteId: string) =>
      apiDelete(`${BASE(tenantId)}/${caseId}/notes/${noteId}`, user?.access_token),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['case-notes', tenantId, caseId] })
      qc.invalidateQueries({ queryKey: ['case-timeline', tenantId, caseId] })
    },
  })
}
