export function ErrorMessage({ error }: { error: Error | null }) {
  if (!error) return null
  return (
    <div className="badge-critical rounded-md border px-4 py-3 text-sm">
      {error.message}
    </div>
  )
}
