import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { userManager } from './oidc'
import { useAuthStore } from './store'

export function Callback() {
  const navigate = useNavigate()
  const { _setUser } = useAuthStore()

  useEffect(() => {
    userManager
      .signinRedirectCallback()
      .then((user) => {
        _setUser(user)
        navigate('/', { replace: true })
      })
      .catch(() => navigate('/', { replace: true }))
  }, [])

  return (
    <div className="flex h-screen items-center justify-center text-gray-500">
      Signing in…
    </div>
  )
}
