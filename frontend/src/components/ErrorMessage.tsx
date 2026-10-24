export function ErrorMessage({ error }: { error: Error | null }) {
  if (!error) return null
  return (
    <div className="rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
      {error.message}
    </div>
  )
}
