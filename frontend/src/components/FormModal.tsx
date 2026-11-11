import type { ReactNode } from 'react'
import { ErrorMessage } from '@/components/ErrorMessage'

interface Props {
  title: string
  submitLabel: string
  onSubmit: () => void
  onCancel: () => void
  canSubmit: boolean
  isPending?: boolean
  error?: Error | null
  children: ReactNode
}

/** Small dialog for the "new / edit" forms. It stays open on error, so nothing typed is lost. */
export function FormModal({
  title,
  submitLabel,
  onSubmit,
  onCancel,
  canSubmit,
  isPending,
  error,
  children,
}: Props) {
  return (
    <div className="modal-backdrop">
      <form
        className="modal max-w-md"
        onSubmit={(e) => {
          e.preventDefault()
          if (canSubmit && !isPending) onSubmit()
        }}
      >
        <h2 className="mb-4 text-lg font-semibold">{title}</h2>
        <div className="space-y-3">{children}</div>
        {error && (
          <div className="mt-3">
            <ErrorMessage error={error} />
          </div>
        )}
        <div className="mt-4 flex justify-end gap-3">
          <button type="button" onClick={onCancel} className="btn btn-ghost">
            Cancel
          </button>
          <button type="submit" disabled={!canSubmit || isPending} className="btn btn-primary">
            {submitLabel}
          </button>
        </div>
      </form>
    </div>
  )
}
