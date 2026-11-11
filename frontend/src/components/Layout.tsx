import type { ReactNode } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { userManager } from '@/auth/oidc'
import { useAuthStore } from '@/auth/store'

const Icon = ({ children }: { children: ReactNode }) => (
  <svg
    viewBox="0 0 16 16"
    className="h-3.5 w-3.5 shrink-0"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    aria-hidden="true"
  >
    {children}
  </svg>
)

interface NavItem {
  writersOnly?: boolean // hidden from viewers
  superOnly?: boolean // hidden from tenant_admin (cross-tenant feature)
  path: string
  label: string
  icon: ReactNode
}

// Raggruppate come nella v10: cosa vedo, cosa gestisco, dove sta la conoscenza.
const GROUPS: { title: string; adminOnly?: boolean; items: NavItem[] }[] = [
  {
    title: 'Intelligence',
    items: [
      {
        path: '/',
        label: 'Dashboard',
        icon: (
          <Icon>
            <rect x="1" y="1" width="6" height="6" rx="1" />
            <rect x="9" y="1" width="6" height="6" rx="1" />
            <rect x="1" y="9" width="6" height="6" rx="1" />
            <rect x="9" y="9" width="6" height="6" rx="1" />
          </Icon>
        ),
      },
      {
        path: '/scores',
        label: 'Scores',
        icon: (
          <Icon>
            <path d="M2 14V8M6 14V4M10 14V7M14 14V2" strokeLinecap="round" />
          </Icon>
        ),
      },
      {
        path: '/exposure',
        label: 'Exposure',
        icon: (
          <Icon>
            <path d="M2 10L6 6L9 9L14 4" />
            <polyline points="12,4 14,4 14,6" />
          </Icon>
        ),
      },
      {
        path: '/analysis',
        label: 'Analysis',
        icon: (
          <Icon>
            <circle cx="7" cy="7" r="4.5" />
            <path d="M10.5 10.5L14 14" strokeLinecap="round" />
          </Icon>
        ),
      },
      {
        path: '/quick-report',
        label: 'Quick Report',
        icon: (
          <Icon>
            <rect x="2" y="1" width="12" height="14" rx="1" />
            <path d="M5 5h6M5 8h4M5 11h2" />
            <path d="M11 10l1.5 1.5L14 9" strokeLinecap="round" strokeLinejoin="round" />
          </Icon>
        ),
      },
    ],
  },
  {
    title: 'Operations',
    items: [
      {
        path: '/assets',
        label: 'Assets',
        icon: (
          <Icon>
            <rect x="2" y="2" width="12" height="5" rx="1" />
            <rect x="2" y="9" width="12" height="5" rx="1" />
            <circle cx="4.5" cy="4.5" r=".6" fill="currentColor" />
            <circle cx="4.5" cy="11.5" r=".6" fill="currentColor" />
          </Icon>
        ),
      },
      {
        path: '/cases',
        label: 'Cases',
        icon: (
          <Icon>
            <rect x="2" y="3" width="12" height="10" rx="1" />
            <path d="M5 3V2M11 3V2M2 7h12" />
          </Icon>
        ),
      },
      {
        path: '/actors',
        label: 'Threat Actors',
        icon: (
          <Icon>
            <circle cx="5" cy="5" r="3" />
            <path d="M1 14v-1a4 4 0 018 0v1" />
            <path d="M12 7c1.1 0 2 .9 2 2s-.9 2-2 2" />
          </Icon>
        ),
      },
      {
        path: '/campaigns',
        label: 'Campaigns',
        icon: (
          <Icon>
            <path d="M1 8h14M8 1l3 7-3 7M5 3L2 8l3 5" />
          </Icon>
        ),
      },
      {
        path: '/dark-web',
        label: 'Dark Web',
        icon: (
          <Icon>
            <circle cx="8" cy="8" r="6" />
            <path d="M8 2C8 2 5.5 5 5.5 8s2.5 6 2.5 6M8 2c0 0 2.5 3 2.5 6s-2.5 6-2.5 6M2 8h12" />
          </Icon>
        ),
      },
      {
        path: '/scanner',
        label: 'Scanner',
        icon: (
          <Icon>
            <rect x="2" y="4" width="12" height="8" rx="1" />
            <path d="M5 8h6M8 6v4" strokeLinecap="round" />
          </Icon>
        ),
      },
      {
        path: '/redteam',
        label: 'Red Team',
        writersOnly: true,
        icon: (
          <Icon>
            <path d="M8 2l1.5 4.5H14l-3.75 2.72 1.44 4.43L8 11.1l-3.69 2.65 1.44-4.43L2 6.5h4.5z" />
          </Icon>
        ),
      },
    ],
  },
  {
    title: 'Knowledge Base',
    items: [
      {
        path: '/observables',
        label: 'Observables',
        icon: (
          <Icon>
            <circle cx="5" cy="8" r="2.5" />
            <circle cx="11" cy="8" r="2.5" />
            <path d="M5 5.5V2M5 10.5V14M11 5.5V2M11 10.5V14" />
          </Icon>
        ),
      },
      {
        path: '/graph',
        label: 'Graph',
        icon: (
          <Icon>
            <circle cx="3" cy="8" r="1.8" />
            <circle cx="13" cy="3.5" r="1.8" />
            <circle cx="13" cy="12.5" r="1.8" />
            <path d="M4.6 7.2L11.4 4.3M4.6 8.8l6.8 3.9" />
          </Icon>
        ),
      },
      {
        path: '/attack',
        label: 'ATT&CK Heatmap',
        icon: (
          <Icon>
            <rect x="1.5" y="1.5" width="4" height="4" />
            <rect x="6.5" y="1.5" width="4" height="4" />
            <rect x="11.5" y="1.5" width="3" height="4" />
            <rect x="1.5" y="6.5" width="4" height="4" />
            <rect x="6.5" y="6.5" width="4" height="4" />
            <rect x="11.5" y="6.5" width="3" height="4" />
          </Icon>
        ),
      },
      {
        path: '/stix',
        label: 'STIX',
        writersOnly: true,
        icon: (
          <Icon>
            <path d="M8 2v8M5 7l3 3 3-3M2 12v2h12v-2" strokeLinecap="round" strokeLinejoin="round" />
          </Icon>
        ),
      },
      {
        path: '/reports',
        label: 'Reports',
        icon: (
          <Icon>
            <rect x="2" y="1" width="12" height="14" rx="1" />
            <path d="M5 5h6M5 8h6M5 11h3" />
          </Icon>
        ),
      },
    ],
  },
  {
    title: 'Administration',
    adminOnly: true,
    items: [
      {
        path: '/clients',
        label: 'Clients',
        superOnly: true,
        icon: (
          <Icon>
            <rect x="1.5" y="6" width="4.5" height="8" />
            <rect x="6.5" y="2" width="4.5" height="12" />
            <rect x="11.5" y="8" width="3" height="6" />
          </Icon>
        ),
      },
      {
        path: '/management',
        label: 'Management',
        icon: (
          <Icon>
            <circle cx="8" cy="8" r="2" />
            <path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4" strokeLinecap="round" />
          </Icon>
        ),
      },
      {
        path: '/connectors',
        label: 'Connectors',
        icon: (
          <Icon>
            <circle cx="4" cy="8" r="2" />
            <circle cx="12" cy="4" r="2" />
            <circle cx="12" cy="12" r="2" />
            <path d="M6 8h2M10 4H8M10 12H8M8 8v-4M8 8v4" strokeLinecap="round" />
          </Icon>
        ),
      },
    ],
  },
]

const ALL_ITEMS = GROUPS.flatMap((g) => g.items)

export function Layout() {
  const { user, hasRole } = useAuthStore()
  const isSuper = hasRole('super_admin')
  const isAdmin = hasRole('tenant_admin') || isSuper
  const canWrite = isAdmin || hasRole('analyst')
  const { pathname } = useLocation()
  const current = ALL_ITEMS.find((i) => (i.path === '/' ? pathname === '/' : pathname.startsWith(i.path)))

  return (
    <div className="flex h-screen flex-col">
      <header
        className="flex h-12 shrink-0 items-center justify-between px-[18px]"
        style={{ background: 'rgba(11,14,20,.92)', borderBottom: '1px solid var(--border)' }}
      >
        <div className="flex items-center gap-[9px] text-[0.82rem] font-semibold tracking-[0.06em]">
          <span
            className="flex h-[26px] w-[26px] items-center justify-center rounded-md"
            style={{
              background: 'linear-gradient(135deg, rgba(82,182,255,.2), rgba(47,111,237,.1))',
              border: '1px solid rgba(82,182,255,.28)',
              color: 'var(--accent)',
            }}
          >
            <svg viewBox="0 0 16 16" className="h-[13px] w-[13px]" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M8 1.5L13.5 4v4c0 3.2-2.3 5.4-5.5 6.5C4.8 13.4 2.5 11.2 2.5 8V4L8 1.5z" />
            </svg>
          </span>
          <span>MEITAKA</span>
          <span className="muted text-[0.72rem] font-normal">CTI</span>
        </div>
        <div className="mono flex items-center gap-3 text-[0.74rem]" style={{ color: 'var(--text3)' }}>
          <span>{(user?.profile as any)?.preferred_username ?? 'User'}</span>
          <button
            onClick={() => userManager.signoutRedirect()}
            className="rounded px-2 py-0.5 hover:bg-white/5 hover:text-slate-200"
          >
            Logout
          </button>
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        <aside
          className="flex w-48 shrink-0 flex-col overflow-y-auto py-1.5"
          style={{ background: 'rgba(15,20,32,.96)', borderRight: '1px solid var(--border)' }}
        >
          {GROUPS.filter((g) => !g.adminOnly || isAdmin).map((group) => (
            <div key={group.title}>
              <div
                className="px-[13px] pb-[3px] pt-[9px] text-[0.65rem] font-bold uppercase tracking-[0.1em]"
                style={{ color: 'var(--text3)' }}
              >
                {group.title}
              </div>
              {group.items
                .filter((i) => !i.writersOnly || canWrite)
                .filter((i) => !i.superOnly || isSuper)
                .map(({ path, label, icon }) => (
                <NavLink
                  key={path}
                  to={path}
                  end={path === '/'}
                  className={({ isActive }) =>
                    `relative mx-[5px] my-px flex items-center gap-[9px] rounded-md border px-[13px] py-1.5 text-[0.8rem] ${
                      isActive
                        ? 'border-[rgba(82,182,255,.1)] bg-[var(--accent-dim)] font-medium text-[var(--accent)]'
                        : 'border-transparent text-[var(--text3)] hover:bg-white/[.03] hover:text-[var(--text2)]'
                    }`
                  }
                >
                  {icon}
                  <span>{label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <div
            className="flex shrink-0 items-center px-[18px] py-[11px]"
            style={{ background: 'rgba(15,20,32,.7)', borderBottom: '1px solid var(--border)' }}
          >
            <h1 className="page-title">{current?.label ?? 'Meitaka CTI'}</h1>
          </div>
          <main className="flex-1 overflow-y-auto p-[18px]">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  )
}
