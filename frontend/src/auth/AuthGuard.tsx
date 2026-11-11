import { useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import { userManager } from './oidc'
import { useAuthStore } from './store'
import type { User } from 'oidc-client-ts'

export function AuthGuard() {
  const { user, isLoading, _setUser, _setLoading } = useAuthStore()

  useEffect(() => {
    userManager.getUser().then((u) => {
      _setUser(u)
      _setLoading(false)
    })
    const onLoaded = (u: User) => _setUser(u)
    const onUnloaded = () => _setUser(null)
    userManager.events.addUserLoaded(onLoaded)
    userManager.events.addUserUnloaded(onUnloaded)
    return () => {
      userManager.events.removeUserLoaded(onLoaded)
      userManager.events.removeUserUnloaded(onUnloaded)
    }
  }, [])

  if (isLoading) {
    return <div className="flex h-screen items-center justify-center muted">Loading…</div>
  }
  if (!user) {
    userManager.signinRedirect()
    return null
  }
  return <Outlet />
}
