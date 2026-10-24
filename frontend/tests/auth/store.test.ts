import { renderHook, act } from '@testing-library/react'
import { useAuthStore } from '@/auth/store'

test('hasRole returns true for matching role in profile.roles', () => {
  const { result } = renderHook(() => useAuthStore())
  act(() => {
    result.current._setUser({
      profile: { sub: '1', roles: ['analyst'] },
      access_token: 'tok',
    } as any)
  })
  expect(result.current.hasRole('analyst')).toBe(true)
  expect(result.current.hasRole('super_admin')).toBe(false)
})

test('hasRole falls back to realm_access.roles', () => {
  const { result } = renderHook(() => useAuthStore())
  act(() => {
    result.current._setUser({
      profile: { sub: '1', realm_access: { roles: ['viewer'] } },
      access_token: 'tok',
    } as any)
  })
  expect(result.current.hasRole('viewer')).toBe(true)
})

test('hasRole returns false when user is null', () => {
  const { result } = renderHook(() => useAuthStore())
  act(() => { result.current._setUser(null) })
  expect(result.current.hasRole('analyst')).toBe(false)
})
