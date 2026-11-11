import { useMemo, useState } from 'react'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useAuthStore } from '@/auth/store'
import {
  useGraph,
  useLinkableIndicators,
  useLinkIndicator,
  useUnlinkIndicator,
} from '@/api/hooks/useGraph'
import type { GraphEdge, GraphNode } from '@/api/types'

// Three columns, left to right: who (actors) -> what they run (campaigns) -> what we saw (indicators).
const COL_X = { threat_actor: 150, campaign: 470, indicator: 790 } as const
const ROW = 36
const TOP = 46
const WIDTH = 940
const COLOR = { threat_actor: 'var(--critical)', campaign: 'var(--accent)', indicator: 'var(--medium)' } as const
const TITLE = { threat_actor: 'Threat actors', campaign: 'Campaigns', indicator: 'Indicators seen in campaigns' } as const
const short = (s: string, n = 26) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)

export function KnowledgeGraph({ tenantId }: { tenantId: string }) {
  const { hasRole } = useAuthStore()
  const canWrite = hasRole('analyst') || hasRole('tenant_admin') || hasRole('super_admin')
  const { data, isLoading, error } = useGraph(tenantId)
  const link = useLinkIndicator(tenantId)
  const unlink = useUnlinkIndicator(tenantId)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [pick, setPick] = useState('')

  const layout = useMemo(() => {
    const nodes = data?.nodes ?? []
    const pos = new Map<string, { x: number; y: number }>()
    const counts = { threat_actor: 0, campaign: 0, indicator: 0 }
    for (const n of nodes) pos.set(n.id, { x: COL_X[n.type], y: TOP + ROW * counts[n.type]++ })
    return { pos, rows: Math.max(counts.threat_actor, counts.campaign, counts.indicator, 1) }
  }, [data])

  const nodes = data?.nodes ?? []
  const edges = data?.edges ?? []
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const selected = selectedId ? byId.get(selectedId) ?? null : null
  const touching = (id: string) => edges.filter((e) => e.source === id || e.target === id)
  const related = (id: string, kind: GraphEdge['type'], side: 'source' | 'target') =>
    edges
      .filter((e) => e.type === kind && e[side] === id)
      .map((e) => byId.get(side === 'source' ? e.target : e.source))
      .filter((n): n is GraphNode => !!n)
  const active = new Set(selected ? touching(selected.id).flatMap((e) => [e.source, e.target]) : [])

  const linkedToSelected = new Set(
    selected?.type === 'campaign' ? related(selected.id, 'indicates', 'target').map((n) => n.id) : [],
  )
  const options = useLinkableIndicators(tenantId, canWrite && selected?.type === 'campaign')
  const free = (options.data?.items ?? []).filter((i) => !linkedToSelected.has(i.id))

  const height = TOP + ROW * layout.rows + 20

  return (
    <div>
      <p className="muted mb-3 text-sm">
        Who is behind what: a campaign points to its threat actor, and the indicators seen in it
        point to the campaign. Click a node to see its connections.
        {canWrite && ' To connect an indicator, select a campaign.'}
      </p>
      <ErrorMessage error={(error ?? link.error ?? unlink.error) as Error | null} />
      {isLoading && <div className="py-10 text-center muted">Loading…</div>}
      {!isLoading && nodes.length === 0 && (
        <div className="card muted text-sm">
          Nothing to show yet. Add threat actors and campaigns, or import a STIX bundle, then connect
          indicators to campaigns.
        </div>
      )}
      {data?.truncated && (
        <p className="mb-2 text-sm" style={{ color: 'var(--medium)' }}>
          {data.indicators_total} indicators are connected; only the first {nodes.filter((n) => n.type === 'indicator').length} are drawn.
        </p>
      )}

      {nodes.length > 0 && (
        <div className="flex flex-col gap-4 lg:flex-row">
          <div className="card min-w-0 flex-1 overflow-auto p-2">
            <svg viewBox={`0 0 ${WIDTH} ${height}`} width="100%" role="group" aria-label="Knowledge graph" style={{ minWidth: 700 }}>
              {(Object.keys(TITLE) as (keyof typeof TITLE)[]).map((k) => (
                <text key={k} x={COL_X[k]} y={22} textAnchor="middle" fill="var(--text3)" fontSize="11" fontWeight="700" letterSpacing="1">
                  {TITLE[k].toUpperCase()}
                </text>
              ))}
              {edges.map((e) => {
                const a = layout.pos.get(e.source)
                const b = layout.pos.get(e.target)
                if (!a || !b) return null
                // the target of both edge kinds (actor, campaign) sits in the column to the left of its source
                const [from, to] = [b, a]
                const x1 = from.x + 105
                const x2 = to.x - 105
                const lit = !selected || e.source === selected.id || e.target === selected.id
                return (
                  <path
                    key={`${e.type}-${e.source}-${e.target}`}
                    d={`M${x1},${from.y} C${(x1 + x2) / 2},${from.y} ${(x1 + x2) / 2},${to.y} ${x2},${to.y}`}
                    fill="none"
                    stroke={e.type === 'indicates' ? 'var(--medium)' : 'var(--critical)'}
                    strokeOpacity={lit ? 0.75 : 0.12}
                    strokeWidth={lit && selected ? 2 : 1.2}
                  />
                )
              })}
              {nodes.map((n) => {
                const p = layout.pos.get(n.id)!
                const dim = selected && n.id !== selected.id && !active.has(n.id)
                return (
                  <g
                    key={n.id}
                    role="button"
                    tabIndex={0}
                    aria-label={`${n.type.replace('_', ' ')} ${n.label}`}
                    aria-pressed={n.id === selectedId}
                    onClick={() => setSelectedId(n.id === selectedId ? null : n.id)}
                    onKeyDown={(ev) => {
                      if (ev.key === 'Enter' || ev.key === ' ') {
                        ev.preventDefault()
                        setSelectedId(n.id === selectedId ? null : n.id)
                      }
                    }}
                    style={{ cursor: 'pointer', outline: 'none' }}
                    opacity={dim ? 0.3 : 1}
                  >
                    <title>{n.label}</title>
                    <rect
                      x={p.x - 105}
                      y={p.y - 13}
                      width={210}
                      height={26}
                      rx={6}
                      fill="var(--bg3)"
                      stroke={COLOR[n.type]}
                      strokeWidth={n.id === selectedId ? 2.5 : 1}
                      strokeDasharray={n.own ? undefined : '4 3'}
                    />
                    <text x={p.x} y={p.y + 4} textAnchor="middle" fill="var(--text)" fontSize="12">
                      {short(n.type === 'indicator' && n.detail ? `${n.detail}: ${n.label}` : n.label, 30)}
                    </text>
                  </g>
                )
              })}
            </svg>
            <p className="muted px-2 pb-1 text-xs">Dashed outline = shared catalog or feed, solid = created by your organisation.</p>
          </div>

          {selected && (
            <aside className="card w-full shrink-0 lg:w-80" aria-label="Node details">
              <div className="mb-2 flex items-start justify-between gap-2">
                <div>
                  <div className="muted text-xs uppercase">{selected.type.replace('_', ' ')}</div>
                  <div className="font-medium break-all">{selected.label}</div>
                </div>
                <button className="btn btn-ghost" onClick={() => setSelectedId(null)} aria-label="Close details">✕</button>
              </div>

              {selected.type === 'threat_actor' && (
                <List title="Campaigns" nodes={related(selected.id, 'attributed-to', 'target')} onPick={setSelectedId} />
              )}
              {selected.type === 'indicator' && (
                <List title="Seen in campaigns" nodes={related(selected.id, 'indicates', 'source')} onPick={setSelectedId} />
              )}
              {selected.type === 'campaign' && (
                <>
                  <List title="Attributed to" nodes={related(selected.id, 'attributed-to', 'source')} onPick={setSelectedId} />
                  <List
                    title="Indicators"
                    nodes={related(selected.id, 'indicates', 'target')}
                    onPick={setSelectedId}
                    action={
                      canWrite
                        ? (n) => (
                            <button
                              className="link-danger text-xs"
                              onClick={() => unlink.mutate({ campaignId: selected.id, indicatorId: n.id })}
                            >
                              Unlink
                            </button>
                          )
                        : undefined
                    }
                  />
                  {canWrite && (
                    <div className="mt-3 space-y-2">
                      <select
                        className="field"
                        aria-label="Indicator to connect"
                        value={pick}
                        onChange={(e) => setPick(e.target.value)}
                      >
                        <option value="">Connect an indicator…</option>
                        {free.map((i) => (
                          <option key={i.id} value={i.id}>{`${i.ioc_type}: ${short(i.value, 40)}`}</option>
                        ))}
                      </select>
                      <button
                        className="btn btn-primary"
                        disabled={!pick || link.isPending}
                        onClick={() =>
                          link.mutate({ campaignId: selected.id, indicatorId: pick }, { onSuccess: () => setPick('') })
                        }
                      >
                        Connect
                      </button>
                    </div>
                  )}
                </>
              )}
            </aside>
          )}
        </div>
      )}
    </div>
  )
}

function List({
  title,
  nodes,
  onPick,
  action,
}: {
  title: string
  nodes: GraphNode[]
  onPick: (id: string) => void
  action?: (n: GraphNode) => React.ReactNode
}) {
  return (
    <div className="mt-3">
      <div className="muted mb-1 text-xs uppercase">{title}</div>
      {nodes.length === 0 ? (
        <p className="muted text-sm">None.</p>
      ) : (
        <ul className="space-y-1">
          {nodes.map((n) => (
            <li key={n.id} className="flex items-center justify-between gap-2 text-sm">
              <button className="link text-left break-all" onClick={() => onPick(n.id)}>
                {n.type === 'indicator' && n.detail ? `${n.detail}: ${n.label}` : n.label}
              </button>
              {action?.(n)}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
