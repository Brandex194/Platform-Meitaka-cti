import { useState } from 'react'
import { ErrorMessage } from '@/components/ErrorMessage'
import { SeverityBadge } from '@/components/SeverityBadge'
import { SlaBadge } from '@/components/SlaBadge'
import { useAuthStore } from '@/auth/store'
import {
  useAddNote,
  useCaseNotes,
  useCaseTimeline,
  useDeleteNote,
  useUpdateCase,
} from '@/api/hooks/useCases'
import type { Case, CaseEvent } from '@/api/types'

const STATUS_LABEL: Record<string, string> = {
  open: 'Open',
  in_progress: 'In analysis',
  closed: 'Closed',
  false_positive: 'False positive',
}

/** One line of the timeline, in words: what happened, with the from/to when there is one. */
export function describeEvent(e: CaseEvent): string {
  const p = (e.payload ?? {}) as Record<string, unknown>
  const status = (v: unknown) => STATUS_LABEL[String(v)] ?? String(v)
  switch (e.event_type) {
    case 'created':
      return `Case created (${p.severity ?? 'medium'})`
    case 'status_changed':
      return `Status: ${status(p.from)} → ${status(p.to)}`
    case 'severity_changed':
      return `Severity: ${p.from} → ${p.to}`
    case 'edited':
      return `Edited ${(p.fields as string[] | undefined)?.join(', ') ?? 'the case'}`
    case 'note_added':
      return 'Note added'
    case 'note_deleted':
      return 'Note deleted'
    default:
      return e.event_type
  }
}

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '—')

interface Props {
  tenantId: string
  item: Case
  onClose: () => void
}

export function CaseDetail({ tenantId, item, onClose }: Props) {
  const { user, hasRole } = useAuthStore()
  const [tab, setTab] = useState<'notes' | 'timeline'>('notes')
  const [draft, setDraft] = useState('')
  const notes = useCaseNotes(tenantId, item.id)
  const timeline = useCaseTimeline(tenantId, item.id)
  const addNote = useAddNote(tenantId, item.id)
  const deleteNote = useDeleteNote(tenantId, item.id)
  const update = useUpdateCase(tenantId)

  const isAdmin = hasRole('tenant_admin') || hasRole('super_admin')
  const canWrite = isAdmin || hasRole('analyst')
  const me = (user?.profile as { sub?: string } | undefined)?.sub
  const closed = item.status === 'closed' || item.status === 'false_positive'
  const setStatus = (status: string) => update.mutate({ id: item.id, status })

  return (
    <aside
      className="card fixed bottom-0 right-0 top-12 z-40 flex w-[420px] max-w-full flex-col overflow-y-auto rounded-none border-y-0 border-r-0"
      aria-label="Case detail"
    >
      <div className="mb-3 flex items-start justify-between gap-3">
        <h2 className="text-base font-semibold">{item.title}</h2>
        <button className="btn btn-ghost" onClick={onClose} aria-label="Close detail">
          ✕
        </button>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="badge badge-neutral">{STATUS_LABEL[item.status] ?? item.status}</span>
        <SeverityBadge severity={item.severity} />
        <SlaBadge status={item.sla_status} />
      </div>
      <dl className="mb-3 grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
        <dt className="muted">Created</dt>
        <dd>{fmt(item.created_at)}</dd>
        <dt className="muted">SLA deadline</dt>
        <dd>{fmt(item.due_at)}</dd>
        {closed && (
          <>
            <dt className="muted">Closed</dt>
            <dd>{fmt(item.closed_at)}</dd>
          </>
        )}
      </dl>
      {item.description && (
        <p className="mb-3 whitespace-pre-wrap text-sm" style={{ color: 'var(--text2)' }}>
          {item.description}
        </p>
      )}

      {canWrite && (
        <div className="mb-4 flex flex-wrap gap-2">
          {!closed && item.status !== 'in_progress' && (
            <button className="btn btn-primary" onClick={() => setStatus('in_progress')}>
              Analyze
            </button>
          )}
          {!closed && (
            <>
              <button className="btn btn-ok" onClick={() => setStatus('closed')}>
                Close
              </button>
              <button className="btn btn-ghost" onClick={() => setStatus('false_positive')}>
                False positive
              </button>
            </>
          )}
          {closed && (
            <button className="btn btn-primary" onClick={() => setStatus('open')}>
              Reopen
            </button>
          )}
        </div>
      )}
      <ErrorMessage error={update.error as Error | null} />

      <div className="mb-3 flex gap-1 border-b" style={{ borderColor: 'var(--border)' }}>
        {(['notes', 'timeline'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-1.5 text-[0.8rem] ${tab === t ? 'font-medium' : 'muted'}`}
            style={tab === t ? { color: 'var(--accent)', borderBottom: '2px solid var(--accent)' } : undefined}
          >
            {t === 'notes' ? 'Notes' : 'Timeline'}
          </button>
        ))}
      </div>

      {tab === 'notes' && (
        <div className="space-y-3">
          {canWrite && (
            <div className="space-y-2">
              <textarea
                className="field"
                rows={3}
                placeholder="Write a note…"
                aria-label="New note"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
              />
              <div className="flex justify-end">
                <button
                  className="btn btn-primary"
                  disabled={!draft.trim() || addNote.isPending}
                  onClick={() => addNote.mutate(draft.trim(), { onSuccess: () => setDraft('') })}
                >
                  Add note
                </button>
              </div>
              <ErrorMessage error={addNote.error as Error | null} />
            </div>
          )}
          <ErrorMessage error={(notes.error ?? deleteNote.error) as Error | null} />
          {(notes.data?.items ?? []).length === 0 && !notes.isLoading && (
            <p className="muted text-sm">No notes yet.</p>
          )}
          {(notes.data?.items ?? []).map((n) => (
            <div key={n.id} className="rounded-md border p-3" style={{ borderColor: 'var(--border)', background: 'var(--bg3)' }}>
              <p className="whitespace-pre-wrap text-sm">{n.body}</p>
              <div className="mt-2 flex items-center justify-between text-xs muted">
                <span>{fmt(n.created_at)}</span>
                {canWrite && (isAdmin || (me && n.author_id === me)) && (
                  <button className="link-danger" onClick={() => deleteNote.mutate(n.id)}>
                    Delete note
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === 'timeline' && (
        <ol className="space-y-2">
          <ErrorMessage error={timeline.error as Error | null} />
          {(timeline.data?.items ?? []).map((e) => (
            <li key={e.id} className="flex gap-3 text-sm">
              <span className="muted w-36 shrink-0 text-xs">{fmt(e.created_at)}</span>
              <span>{describeEvent(e)}</span>
            </li>
          ))}
        </ol>
      )}
    </aside>
  )
}
