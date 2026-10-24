import { create } from 'zustand'
import type { User } from 'oidc-client-ts'

interface AuthState {
  user: User | null
  isLoading: boolean
  hasRole: (role: string) => boolean
  _setUser: (user: User | null) => void
  _setLoading: (v: boolean) => void
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  isLoading: true,
  hasRole: (role) => {
    const u = get().user
    if (!u) return false
    const roles: string[] =
      (u.profile as any).roles ??
      (u.profile as any).realm_access?.roles ??
      []
    return roles.includes(role)
  },
  _setUser: (user) => set({ user }),
  _setLoading: (isLoading) => set({ isLoading }),
}))
