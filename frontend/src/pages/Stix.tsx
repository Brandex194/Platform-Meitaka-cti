import { useRef, useState } from 'react'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useAuthStore } from '@/auth/store'
import { downloadStix, useImportStix } from '@/api/hooks/useStix'
import type { StixCounts } from '@/api/types'

const MAX_FILE_BYTES = 10 * 1024 * 1024

const readText = (file: File) =>
  new Promise<string>((resolve, reject) => {
    const r = new FileReader()
    r.onload = () => resolve(String(r.result))
    r.onerror = () => reject(r.error)
    r.readAsText(file)
  })

const CountsRow = ({ label, c }: { label: string; c: StixCounts }) => (
  <tr>
    <td>{label}</td>
    <td>{c.indicators}</td>
    <td>{c.threat_actors}</td>
    <td>{c.campaigns}</td>
    <td>{c.links}</td>
  </tr>
)

export function Stix({ tenantId }: { tenantId: string }) {
  const { user, hasRole } = useAuthStore()
  const canUse = hasRole('analyst') || hasRole('tenant_admin') || hasRole('super_admin')
  const imp = useImportStix(tenantId)
  const fileRef = useRef<HTMLInputElement>(null)
  const [ownOnly, setOwnOnly] = useState(false)
  const [exportError, setExportError] = useState<Error | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [fileName, setFileName] = useState<string | null>(null)

  if (!canUse) return <p className="muted">STIX import and export are available to analysts and administrators.</p>

  const onFile = async (file: File | undefined) => {
    setFileError(null)
    imp.reset()
    if (!file) return
    setFileName(file.name)
    if (file.size > MAX_FILE_BYTES) {
      setFileError('The file is larger than 10 MB.')
      return
    }
    let bundle: unknown
    try {
      bundle = JSON.parse(await readText(file))
    } catch {
      setFileError('The file is not valid JSON.')
      return
    }
    imp.mutate(bundle)
  }

  const result = imp.data
  return (
    <div className="space-y-5">
      <section className="card">
        <h2 className="mb-1 text-base font-semibold">Export</h2>
        <p className="muted mb-3 text-sm">
          Download a STIX 2.1 bundle with indicators, threat actors and campaigns, to share with
          another team or load into another tool.
        </p>
        <label className="mb-3 flex items-center gap-2 text-sm">
          <input type="checkbox" checked={ownOnly} onChange={(e) => setOwnOnly(e.target.checked)} />
          Only what my organisation created (leave out the shared catalog and the feeds)
        </label>
        <button
          className="btn btn-primary"
          onClick={() => {
            setExportError(null)
            downloadStix(tenantId, user?.access_token, ownOnly).catch((e) => setExportError(e))
          }}
        >
          Download bundle
        </button>
        <ErrorMessage error={exportError} />
      </section>

      <section className="card">
        <h2 className="mb-1 text-base font-semibold">Import</h2>
        <p className="muted mb-3 text-sm">
          Load a STIX 2.1 bundle (.json, up to 10 MB). Indicators with one simple pattern, threat
          actors, campaigns, their attribution and the indicators seen in each campaign are stored as yours. Anything already present is
          left alone, and whatever cannot be stored is listed below with the reason.
        </p>
        <input
          ref={fileRef}
          type="file"
          accept=".json,application/json,application/stix+json"
          aria-label="STIX bundle file"
          className="field"
          onChange={(e) => {
            const f = e.target.files?.[0]
            void onFile(f)
            e.target.value = '' // lets the same file be chosen again
          }}
        />
        {imp.isPending && <p className="muted mt-3 text-sm">Importing {fileName}…</p>}
        {fileError && <p className="mt-3 text-sm" style={{ color: 'var(--critical)' }}>{fileError}</p>}
        <ErrorMessage error={imp.error as Error | null} />

        {result && (
          <div className="mt-4" aria-label="Import result">
            <div className="table-wrap mb-3">
              <table>
                <thead>
                  <tr><th></th><th>Indicators</th><th>Threat actors</th><th>Campaigns</th><th>Links</th></tr>
                </thead>
                <tbody>
                  <CountsRow label="Created" c={result.created} />
                  <CountsRow label="Already present" c={result.duplicates} />
                </tbody>
              </table>
            </div>
            {result.skipped_total > 0 && (
              <>
                <p className="mb-2 text-sm">
                  {result.skipped_total} object{result.skipped_total === 1 ? '' : 's'} not imported
                  {result.skipped.length < result.skipped_total ? ` (first ${result.skipped.length} shown)` : ''}:
                </p>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr><th>Type</th><th>Id</th><th>Reason</th></tr>
                    </thead>
                    <tbody>
                      {result.skipped.map((s, i) => (
                        <tr key={`${s.id}-${i}`}>
                          <td>{s.type}</td>
                          <td><code className="mono text-xs">{s.id}</code></td>
                          <td>{s.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        )}
      </section>
    </div>
  )
}
