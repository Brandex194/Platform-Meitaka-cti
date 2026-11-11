interface Props { title: string; message: string; onConfirm: () => void; onCancel: () => void }

export function ConfirmModal({ title, message, onConfirm, onCancel }: Props) {
  return (
    <div className="modal-backdrop">
      <div className="modal max-w-sm">
        <h2 className="mb-2 text-lg font-semibold">{title}</h2>
        <p className="mb-6 text-sm muted">{message}</p>
        <div className="flex justify-end gap-3">
          <button onClick={onCancel} className="btn btn-ghost">
            Cancel
          </button>
          <button onClick={onConfirm} className="btn btn-danger">
            Confirm
          </button>
        </div>
      </div>
    </div>
  )
}
