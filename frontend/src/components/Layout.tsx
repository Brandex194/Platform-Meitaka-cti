import { NavLink, Outlet } from 'react-router-dom'
import { userManager } from '@/auth/oidc'
import { useAuthStore } from '@/auth/store'

const NAV = [
  { path: '/', label: 'Dashboard' },
  { path: '/assets', label: 'Assets' },
  { path: '/scores', label: 'Scores' },
  { path: '/exposure', label: 'Exposure' },
  { path: '/analysis', label: 'Analysis' },
  { path: '/cases', label: 'Cases' },
  { path: '/actors', label: 'Actors' },
  { path: '/campaigns', label: 'Campaigns' },
  { path: '/observables', label: 'Observables' },
  { path: '/dark-web', label: 'Dark Web' },
  { path: '/reports', label: 'Reports' },
]

export function Layout() {
  const { user } = useAuthStore()
  return (
    <div className="flex h-screen">
      <aside className="flex w-56 flex-col bg-gray-900 text-gray-100">
        <div className="px-4 py-5 text-lg font-bold tracking-wide">Sentinel AI</div>
        <nav className="flex-1 space-y-0.5 px-2">
          {NAV.map(({ path, label }) => (
            <NavLink
              key={path}
              to={path}
              end={path === '/'}
              className={({ isActive }) =>
                `block rounded px-3 py-2 text-sm ${isActive ? 'bg-gray-700 text-white' : 'text-gray-300 hover:bg-gray-800'}`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-gray-700 px-4 py-3 text-xs text-gray-400">
          {(user?.profile as any)?.preferred_username ?? 'User'}
          <button
            onClick={() => userManager.signoutRedirect()}
            className="ml-3 text-gray-500 hover:text-gray-300"
          >
            Logout
          </button>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto bg-gray-50 p-6">
        <Outlet />
      </main>
    </div>
  )
}
