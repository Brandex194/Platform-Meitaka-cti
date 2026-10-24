import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { vi } from 'vitest'
import { AuthGuard } from '@/auth/AuthGuard'
import { useAuthStore } from '@/auth/store'

vi.mock('@/auth/store')
vi.mock('@/auth/oidc', () => ({
  userManager: {
    signinRedirect: vi.fn(),
    getUser: vi.fn().mockResolvedValue(null),
    events: {
      addUserLoaded: vi.fn(),
      addUserUnloaded: vi.fn(),
      removeUserLoaded: vi.fn(),
      removeUserUnloaded: vi.fn(),
    },
  },
}))

test('renders children when authenticated', () => {
  vi.mocked(useAuthStore).mockReturnValue({
    user: { profile: { sub: '1' }, access_token: 'tok' } as any,
    isLoading: false,
    hasRole: () => true,
    _setUser: vi.fn(),
    _setLoading: vi.fn(),
  })
  render(
    <MemoryRouter initialEntries={['/']}>
      <Routes>
        <Route element={<AuthGuard />}>
          <Route path="/" element={<div>protected</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
  expect(screen.getByText('protected')).toBeInTheDocument()
})

test('calls signinRedirect when unauthenticated and not loading', async () => {
  const { userManager } = await import('@/auth/oidc')
  vi.mocked(useAuthStore).mockReturnValue({
    user: null,
    isLoading: false,
    hasRole: () => false,
    _setUser: vi.fn(),
    _setLoading: vi.fn(),
  })
  render(
    <MemoryRouter initialEntries={['/']}>
      <Routes>
        <Route element={<AuthGuard />}>
          <Route path="/" element={<div>protected</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
  expect(userManager.signinRedirect).toHaveBeenCalled()
  expect(screen.queryByText('protected')).not.toBeInTheDocument()
})
