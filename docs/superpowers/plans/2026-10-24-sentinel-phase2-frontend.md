# Sentinel AI Phase 2 — Frontend Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development to implement task-by-task.

**Goal:** Build the React 19 frontend that reads real CTI data from the Phase 1 backend.
All 14 pages (8 Phase 1 + 6 Phase 2) behind OIDC auth. RBAC enforced in UI.

**Architecture:** Single-page app (Vite + React 19 + TypeScript). OIDC Authorization
Code + PKCE via oidc-client-ts; tokens stored in sessionStorage (not localStorage per
spec §7). Server state via TanStack Query v5. Tables via TanStack Table v8.
Charts via Recharts. Global auth state via Zustand. Backend at `/api/v1/` (proxy via Vite).

**Spec:** `docs/superpowers/specs/2026-10-23-sentinel-ai-design.md`
**Backend:** Phase 1 complete on branch `feature/phase1-backend`.

## Global Constraints

- React 19, Vite 6, TypeScript 5.5 (strict mode)
- TailwindCSS 3; no CSS modules; no styled-components
- TanStack Query v5 for all GET calls; mutations via `useMutation`
- oidc-client-ts 3.x — `UserManager` + `signInRedirect`/`signinRedirectCallback`
- sessionStorage only for OIDC state + access token; never localStorage for auth
- All protected pages wrapped in `<AuthGuard>`; unauthenticated → `UserManager.signinRedirect()`
- RBAC: derive roles from `user.profile.roles ?? user.profile.realm_access?.roles ?? []`
- Viewer (read-only): no CREATE/PATCH/DELETE buttons rendered — not just disabled
- Error model: API returns `{"error":{"code":"…","message":"…","detail":{}}}` — display `error.message`
- Vite proxy: `/api` → `http://localhost:8000` (dev only)
- `vitest` + `@testing-library/react` for all tests; run from `frontend/`
- All git commits end with: `Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>`

---

## File Map

```
frontend/
  package.json
  vite.config.ts
  tsconfig.json
  tailwind.config.ts
  postcss.config.js
  index.html
  .env.example
  src/
    main.tsx                    # ReactDOM.createRoot, QueryClient, Router
    router.tsx                  # createBrowserRouter definition
    index.css                   # Tailwind directives
    auth/
      oidc.ts                   # UserManager singleton
      store.ts                  # Zustand: {user, isLoading, hasRole}
      AuthGuard.tsx             # redirect unauth'd; render children via Outlet
      Callback.tsx              # signinRedirectCallback page
    api/
      client.ts                 # fetch wrapper with Bearer injection
      types.ts                  # all TS interfaces matching backend models
      hooks/
        useDashboard.ts
        useAssets.ts
        useScores.ts
        useExposure.ts
        useCases.ts
        useActors.ts
        useCampaigns.ts
        useIndicators.ts
        useObservations.ts
        useReports.ts
    components/
      Layout.tsx                # sidebar + topbar shell
      DataTable.tsx             # TanStack Table wrapper
      SeverityBadge.tsx
      RiskLevelBadge.tsx
      ScoreSparkline.tsx        # Recharts LineChart sparkline
      ErrorMessage.tsx          # displays API error.message
      ConfirmModal.tsx          # reusable yes/no modal
    pages/
      Dashboard.tsx
      Assets.tsx
      Scores.tsx
      Exposure.tsx
      Analysis.tsx
      Cases.tsx
      Actors.tsx
      Campaigns.tsx
      Observables.tsx
      DarkWeb.tsx
      Reports.tsx
  tests/
    setup.ts
    auth/
      AuthGuard.test.tsx
      store.test.ts
    api/
      client.test.ts
    components/
      DataTable.test.tsx
      SeverityBadge.test.tsx
    pages/
      Dashboard.test.tsx
      Cases.test.tsx
      Exposure.test.tsx
```

## Review Focus

- **OIDC PKCE flow**: `signinRedirect()` must set `state`; callback calls
  `signinRedirectCallback()` before rendering; tokens in sessionStorage, never memory-only.
- **RBAC visibility**: viewer gets no mutation buttons at all (DOM hidden, not just disabled).
- **Token refresh**: `automaticSilentRenew: true` on UserManager; failure redirects to login.
- **TanStack Query stale time**: 60s default for CTI data.
- **PATCH exposure race**: optimistic update + rollback on error (`onMutate`/`onError`).

---

### Task 1: Frontend Scaffold

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/tsconfig.json`
- Create: `frontend/tailwind.config.ts`
- Create: `frontend/postcss.config.js`
- Create: `frontend/index.html`
- Create: `frontend/src/main.tsx`
- Create: `frontend/src/router.tsx`
- Create: `frontend/src/index.css`
- Create: `frontend/tests/setup.ts`
- Create: `frontend/.env.example`

**Interfaces:**
- Produces: `npm run dev` starts on :5173; `npm run build` exits 0; `npm test` exits 0 (0 tests)

- [ ] **Step 1: Write `frontend/package.json`**

  ```json
  {
    "name": "sentinel-ai-frontend",
    "version": "0.1.0",
    "type": "module",
    "scripts": {
      "dev": "vite",
      "build": "tsc -b && vite build",
      "test": "vitest run",
      "test:watch": "vitest"
    },
    "dependencies": {
      "react": "^19.0.0",
      "react-dom": "^19.0.0",
      "react-router-dom": "^6.26.0",
      "oidc-client-ts": "^3.1.0",
      "@tanstack/react-query": "^5.56.0",
      "@tanstack/react-table": "^8.20.0",
      "recharts": "^2.12.0",
      "zustand": "^5.0.0",
      "clsx": "^2.1.1"
    },
    "devDependencies": {
      "@types/react": "^19.0.0",
      "@types/react-dom": "^19.0.0",
      "@vitejs/plugin-react": "^4.3.0",
      "vite": "^6.0.0",
      "typescript": "^5.5.0",
      "tailwindcss": "^3.4.0",
      "autoprefixer": "^10.4.0",
      "postcss": "^8.4.0",
      "vitest": "^2.1.0",
      "@testing-library/react": "^16.0.0",
      "@testing-library/jest-dom": "^6.5.0",
      "msw": "^2.4.0",
      "jsdom": "^25.0.0"
    }
  }
  ```

- [ ] **Step 2: Write `frontend/vite.config.ts`**

  ```typescript
  import { defineConfig } from 'vite'
  import react from '@vitejs/plugin-react'

  export default defineConfig({
    plugins: [react()],
    resolve: { alias: { '@': '/src' } },
    server: {
      proxy: {
        '/api': 'http://localhost:8000',
        '/auth': 'http://localhost:8080',
      },
    },
    test: {
      environment: 'jsdom',
      setupFiles: ['./tests/setup.ts'],
      globals: true,
    },
  })
  ```

- [ ] **Step 3: Write `frontend/tsconfig.json`**

  ```json
  {
    "compilerOptions": {
      "target": "ES2022",
      "lib": ["ES2022", "DOM", "DOM.Iterable"],
      "module": "ESNext",
      "moduleResolution": "bundler",
      "jsx": "react-jsx",
      "strict": true,
      "noUnusedLocals": true,
      "noUnusedParameters": true,
      "noFallthroughCasesInSwitch": true,
      "baseUrl": ".",
      "paths": { "@/*": ["src/*"] }
    },
    "include": ["src"]
  }
  ```

- [ ] **Step 4: Write `frontend/tailwind.config.ts`**

  ```typescript
  import type { Config } from 'tailwindcss'
  export default {
    content: ['./index.html', './src/**/*.{ts,tsx}'],
    theme: { extend: {} },
    plugins: [],
  } satisfies Config
  ```

- [ ] **Step 5: Write `frontend/postcss.config.js`**

  ```javascript
  export default {
    plugins: { tailwindcss: {}, autoprefixer: {} },
  }
  ```

- [ ] **Step 6: Write `frontend/index.html`**

  ```html
  <!doctype html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Sentinel AI</title>
    </head>
    <body>
      <div id="root"></div>
      <script type="module" src="/src/main.tsx"></script>
    </body>
  </html>
  ```

- [ ] **Step 7: Write `frontend/src/index.css`**

  ```css
  @tailwind base;
  @tailwind components;
  @tailwind utilities;
  ```

- [ ] **Step 8: Write `frontend/src/main.tsx`**

  ```typescript
  import React from 'react'
  import ReactDOM from 'react-dom/client'
  import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
  import { RouterProvider } from 'react-router-dom'
  import { router } from './router'
  import './index.css'

  const queryClient = new QueryClient({
    defaultOptions: { queries: { staleTime: 60_000, retry: 1 } },
  })

  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </React.StrictMode>,
  )
  ```

- [ ] **Step 9: Write `frontend/src/router.tsx`** (stub routes)

  ```typescript
  import { createBrowserRouter } from 'react-router-dom'

  export const router = createBrowserRouter([
    { path: '/callback', element: <div>Callback</div> },
    { path: '/', element: <div>Dashboard</div> },
    { path: '/assets', element: <div>Assets</div> },
    { path: '/scores', element: <div>Scores</div> },
    { path: '/exposure', element: <div>Exposure</div> },
    { path: '/analysis', element: <div>Analysis</div> },
    { path: '/cases', element: <div>Cases</div> },
    { path: '/actors', element: <div>Actors</div> },
    { path: '/campaigns', element: <div>Campaigns</div> },
    { path: '/observables', element: <div>Observables</div> },
    { path: '/dark-web', element: <div>DarkWeb</div> },
    { path: '/reports', element: <div>Reports</div> },
  ])
  ```

- [ ] **Step 10: Write `frontend/tests/setup.ts`**

  ```typescript
  import '@testing-library/jest-dom'
  ```

- [ ] **Step 11: Write `frontend/.env.example`**

  ```
  VITE_KEYCLOAK_URL=http://localhost:8080
  VITE_KEYCLOAK_REALM=sentinel
  VITE_KEYCLOAK_CLIENT_ID=sentinel-ai
  ```

- [ ] **Step 12: Run — expect PASS (0 tests)**

  ```bash
  cd frontend && npm install && npm test
  ```
  Expected: `Tests 0 passed`.

- [ ] **Step 13: Verify build**

  ```bash
  npm run build
  ```
  Expected: exits 0, `dist/` created.

- [ ] **Step 14: Commit**

  ```bash
  git add frontend/
  git commit -m "chore: frontend scaffold (Vite + React 19 + TypeScript + Tailwind + Vitest)

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 2: OIDC Auth

**Files:**
- Create: `frontend/src/auth/oidc.ts`
- Create: `frontend/src/auth/store.ts`
- Create: `frontend/src/auth/AuthGuard.tsx`
- Create: `frontend/src/auth/Callback.tsx`

**Interfaces:**
- Produces: `userManager` singleton; `useAuthStore()` → `{user, isLoading, hasRole}`; `<AuthGuard>` redirects unauthenticated; `<Callback>` completes sign-in

- [ ] **Step 1: Write failing tests**

  ```typescript
  // tests/auth/AuthGuard.test.tsx
  import { render, screen } from '@testing-library/react'
  import { MemoryRouter, Routes, Route } from 'react-router-dom'
  import { vi } from 'vitest'
  import { AuthGuard } from '@/auth/AuthGuard'
  import { useAuthStore } from '@/auth/store'

  vi.mock('@/auth/store')
  vi.mock('@/auth/oidc', () => ({ userManager: { signinRedirect: vi.fn(), getUser: vi.fn().mockResolvedValue(null), events: { addUserLoaded: vi.fn(), addUserUnloaded: vi.fn(), removeUserLoaded: vi.fn(), removeUserUnloaded: vi.fn() } } }))

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
  ```

  ```typescript
  // tests/auth/store.test.ts
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
  ```

- [ ] **Step 2: Run — expect FAIL**

  ```bash
  npm test tests/auth/
  ```

- [ ] **Step 3: Implement `src/auth/oidc.ts`**

  ```typescript
  import { UserManager, WebStorageStateStore } from 'oidc-client-ts'

  export const userManager = new UserManager({
    authority: `${import.meta.env.VITE_KEYCLOAK_URL}/realms/${import.meta.env.VITE_KEYCLOAK_REALM}`,
    client_id: import.meta.env.VITE_KEYCLOAK_CLIENT_ID,
    redirect_uri: `${window.location.origin}/callback`,
    response_type: 'code',
    scope: 'openid profile email',
    automaticSilentRenew: true,
    userStore: new WebStorageStateStore({ store: sessionStorage }),
  })
  ```

- [ ] **Step 4: Implement `src/auth/store.ts`**

  ```typescript
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
  ```

- [ ] **Step 5: Implement `src/auth/AuthGuard.tsx`**

  ```typescript
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
      return <div className="flex h-screen items-center justify-center text-gray-500">Loading…</div>
    }
    if (!user) {
      userManager.signinRedirect()
      return null
    }
    return <Outlet />
  }
  ```

- [ ] **Step 6: Implement `src/auth/Callback.tsx`**

  ```typescript
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
  ```

- [ ] **Step 7: Update `src/router.tsx`** to use AuthGuard and Callback

  ```typescript
  import { createBrowserRouter } from 'react-router-dom'
  import { AuthGuard } from './auth/AuthGuard'
  import { Callback } from './auth/Callback'

  export const router = createBrowserRouter([
    { path: '/callback', element: <Callback /> },
    {
      element: <AuthGuard />,
      children: [
        { path: '/', element: <div>Dashboard</div> },
        { path: '/assets', element: <div>Assets</div> },
        { path: '/scores', element: <div>Scores</div> },
        { path: '/exposure', element: <div>Exposure</div> },
        { path: '/analysis', element: <div>Analysis</div> },
        { path: '/cases', element: <div>Cases</div> },
        { path: '/actors', element: <div>Actors</div> },
        { path: '/campaigns', element: <div>Campaigns</div> },
        { path: '/observables', element: <div>Observables</div> },
        { path: '/dark-web', element: <div>DarkWeb</div> },
        { path: '/reports', element: <div>Reports</div> },
      ],
    },
  ])
  ```

- [ ] **Step 8: Run — expect PASS**

  ```bash
  npm test tests/auth/
  ```

- [ ] **Step 9: Commit**

  ```bash
  git add frontend/src/auth/ frontend/src/router.tsx
  git commit -m "feat: OIDC Authorization Code + PKCE auth (oidc-client-ts + Zustand)

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 3: API Client + TypeScript Types

**Files:**
- Create: `frontend/src/api/client.ts`
- Create: `frontend/src/api/types.ts`

**Interfaces:**
- Produces: `apiGet<T>`, `apiPost<T,B>`, `apiPatch<T,B>`, `apiDelete`; all 21 backend model interfaces

- [ ] **Step 1: Write failing tests**

  ```typescript
  // tests/api/client.test.ts
  import { describe, it, expect, vi, beforeEach } from 'vitest'

  const mockFetch = vi.fn()
  vi.stubGlobal('fetch', mockFetch)

  import { apiGet, apiPost } from '@/api/client'

  beforeEach(() => mockFetch.mockReset())

  describe('apiGet', () => {
    it('sets Authorization Bearer header when token provided', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => [] })
      await apiGet('/api/v1/assets', 'tok123')
      const [, init] = mockFetch.mock.calls[0]
      expect((init as RequestInit).headers!['Authorization']).toBe('Bearer tok123')
    })

    it('omits Authorization header when no token', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => [] })
      await apiGet('/api/v1/assets')
      const [, init] = mockFetch.mock.calls[0]
      expect((init as RequestInit).headers!['Authorization']).toBeUndefined()
    })

    it('throws with error.message on non-ok response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: async () => ({ error: { code: 'NOT_FOUND', message: 'not found', detail: {} } }),
      })
      await expect(apiGet('/api/v1/assets')).rejects.toThrow('not found')
    })

    it('throws generic message when error envelope missing', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, json: async () => ({}) })
      await expect(apiGet('/api/v1/assets')).rejects.toThrow('HTTP 500')
    })
  })

  describe('apiPost', () => {
    it('sends JSON body', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({ id: '1' }) })
      await apiPost('/api/v1/cases', { title: 'Test' }, 'tok')
      const [, init] = mockFetch.mock.calls[0]
      expect((init as RequestInit).body).toBe(JSON.stringify({ title: 'Test' }))
    })
  })
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `src/api/client.ts`**

  ```typescript
  async function request<T>(
    method: string,
    path: string,
    token?: string,
    body?: unknown,
  ): Promise<T> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (token) headers['Authorization'] = `Bearer ${token}`
    const res = await fetch(path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
    const json = await res.json()
    if (!res.ok) throw new Error(json?.error?.message ?? `HTTP ${res.status}`)
    return json as T
  }

  export const apiGet = <T>(path: string, token?: string) =>
    request<T>('GET', path, token)
  export const apiPost = <T, B = unknown>(path: string, body: B, token?: string) =>
    request<T>('POST', path, token, body)
  export const apiPatch = <T, B = unknown>(path: string, body: B, token?: string) =>
    request<T>('PATCH', path, token, body)
  export const apiDelete = (path: string, token?: string) =>
    request<void>('DELETE', path, token)
  ```

- [ ] **Step 4: Implement `src/api/types.ts`**

  ```typescript
  // All UUIDs are strings; timestamps are ISO 8601 strings
  export interface Tenant { id: string; name: string; slug: string; sector: string | null; created_at: string }
  export interface Asset { id: string; tenant_id: string; hostname: string | null; ip: string | null; created_at: string }
  export interface Software { id: string; asset_id: string; tenant_id: string; name: string; version: string | null }
  export interface Vulnerability { id: string; cve_id: string; cvss_score: number | null; cvss_vector: string | null; description: string | null; mitre_techniques: string[] | null; kev_date_added: string | null; epss_score: number | null }
  export interface Indicator { id: string; tenant_id: string | null; ioc_type: string; value: string; confidence: number | null; created_at: string }
  export interface Leak { id: string; tenant_id: string; email_hash: string; breach_name: string; pwn_count: number | null; created_at: string }
  export interface CorrelationEvent { id: string; tenant_id: string | null; rule_name: string; asset_id: string | null; identity_id: string | null; vulnerability_id: string | null; indicator_id: string | null; s_context: number | null; is_active: boolean; resolved_at: string | null; created_at: string }
  export interface ExposureMatch { id: string; tenant_id: string; correlation_event_id: string | null; status: string; epss_score: number | null; updated_at: string }
  export interface Score { id: string; tenant_id: string; asset_id: string | null; score_type: string; value: number; level: string; epss_score: number | null; computed_at: string }
  export interface ScoreRule { id: string; tenant_id: string | null; version: number; weights: { severity: number; confidence: number; recency: number; epss: number }; thresholds: { low: number; medium: number; high: number }; created_at: string; created_by: string | null }
  export interface Case { id: string; tenant_id: string; title: string; description: string | null; status: string; severity: string; created_by: string | null; created_at: string; updated_at: string }
  export interface Identity { id: string; tenant_id: string; email: string | null; name: string | null; created_at: string }
  export interface ThreatActor { id: string; name: string; aliases: string[] | null; description: string | null; created_at: string }
  export interface Campaign { id: string; tenant_id: string | null; name: string; threat_actor_id: string | null; description: string | null; created_at: string }
  export interface AttackTechnique { id: string; mitre_id: string; name: string; tactic: string | null; description: string | null }
  export interface Source { id: string; name: string; source_type: string; url: string | null; created_at: string }
  export interface KevCatalog { id: string; cve_id: string; date_added: string | null; updated_at: string }
  export interface FeedbackEvent { id: string; tenant_id: string | null; event_type: string; payload: Record<string, unknown> | null; created_at: string }
  export interface AuditLog { id: string; tenant_id: string | null; actor_id: string | null; action: string; resource_type: string | null; resource_id: string | null; payload: Record<string, unknown> | null; created_at: string }
  export interface PhishingDomain { id: string; tenant_id: string; domain: string; status: string; created_at: string }
  export interface Observation { id: string; tenant_id: string; asset_id: string | null; event_type: string; payload: Record<string, unknown> | null; created_at: string }

  // API response wrappers
  export interface Paginated<T> { items: T[]; total: number; page: number; size: number }
  export interface DashboardData {
    open_cases: number
    critical_scores: number
    active_exposures: number
    recent_events: CorrelationEvent[]
    scores_by_level: { level: string; count: number }[]
  }
  export interface QuickReport {
    tenant_id: string
    generated_at: string
    total_assets: number
    critical_assets: number
    open_cases: number
    top_vulnerabilities: Vulnerability[]
    risk_trend: { date: string; avg_score: number }[]
  }
  ```

- [ ] **Step 5: Run — expect PASS**

  ```bash
  npm test tests/api/
  ```

- [ ] **Step 6: Commit**

  ```bash
  git add frontend/src/api/
  git commit -m "feat: typed API client with Bearer injection and backend model types

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 4: Layout + Shared Components

**Files:**
- Create: `frontend/src/components/Layout.tsx`
- Create: `frontend/src/components/DataTable.tsx`
- Create: `frontend/src/components/SeverityBadge.tsx`
- Create: `frontend/src/components/RiskLevelBadge.tsx`
- Create: `frontend/src/components/ScoreSparkline.tsx`
- Create: `frontend/src/components/ErrorMessage.tsx`
- Create: `frontend/src/components/ConfirmModal.tsx`

**Interfaces:**
- Produces: `<Layout>` renders sidebar nav + `<Outlet>`; `<DataTable<T>>` renders TanStack Table; badge + sparkline components used by all pages

- [ ] **Step 1: Write failing tests**

  ```typescript
  // tests/components/SeverityBadge.test.tsx
  import { render, screen } from '@testing-library/react'
  import { SeverityBadge } from '@/components/SeverityBadge'

  test.each([
    ['critical', 'bg-red-600'],
    ['high', 'bg-orange-500'],
    ['medium', 'bg-yellow-400'],
    ['low', 'bg-green-500'],
  ])('severity %s has correct color class', (severity, cls) => {
    const { container } = render(<SeverityBadge severity={severity} />)
    expect(container.firstChild).toHaveClass(cls)
    expect(screen.getByText(severity)).toBeInTheDocument()
  })
  ```

  ```typescript
  // tests/components/DataTable.test.tsx
  import { render, screen } from '@testing-library/react'
  import { createColumnHelper } from '@tanstack/react-table'
  import { DataTable } from '@/components/DataTable'

  type Row = { id: string; name: string }
  const col = createColumnHelper<Row>()
  const columns = [col.accessor('name', { header: 'Name' })]

  test('renders rows and header', () => {
    render(<DataTable columns={columns} data={[{ id: '1', name: 'Alice' }]} />)
    expect(screen.getByText('Name')).toBeInTheDocument()
    expect(screen.getByText('Alice')).toBeInTheDocument()
  })

  test('shows "No data" when empty', () => {
    render(<DataTable columns={columns} data={[]} />)
    expect(screen.getByText(/no data/i)).toBeInTheDocument()
  })

  test('shows loading spinner when isLoading=true', () => {
    render(<DataTable columns={columns} data={[]} isLoading />)
    expect(screen.getByText(/loading/i)).toBeInTheDocument()
  })
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `src/components/SeverityBadge.tsx`**

  ```typescript
  const COLORS: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-400 text-gray-900',
    low: 'bg-green-500 text-white',
    info: 'bg-blue-400 text-white',
  }

  export function SeverityBadge({ severity }: { severity: string }) {
    const cls = COLORS[severity.toLowerCase()] ?? 'bg-gray-400 text-white'
    return (
      <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${cls}`}>
        {severity}
      </span>
    )
  }
  ```

- [ ] **Step 4: Implement `src/components/RiskLevelBadge.tsx`**

  Same as SeverityBadge; levels map: `critical` → red-600, `high` → orange-500, `medium` → yellow-400, `low` → green-500.

- [ ] **Step 5: Implement `src/components/DataTable.tsx`**

  ```typescript
  import {
    useReactTable,
    getCoreRowModel,
    flexRender,
    type ColumnDef,
  } from '@tanstack/react-table'

  interface Props<T> {
    data: T[]
    columns: ColumnDef<T, any>[]
    isLoading?: boolean
  }

  export function DataTable<T>({ data, columns, isLoading }: Props<T>) {
    const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() })

    if (isLoading) {
      return <div className="py-10 text-center text-gray-400">Loading…</div>
    }

    return (
      <div className="overflow-x-auto rounded-lg border border-gray-200">
        <table className="min-w-full divide-y divide-gray-200 text-sm">
          <thead className="bg-gray-50">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => (
                  <th key={h.id} className="px-4 py-3 text-left font-semibold text-gray-600">
                    {flexRender(h.column.columnDef.header, h.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody className="divide-y divide-gray-100 bg-white">
            {table.getRowModel().rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="py-10 text-center text-gray-400">
                  No data
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => (
                <tr key={row.id} className="hover:bg-gray-50">
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-4 py-3">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    )
  }
  ```

- [ ] **Step 6: Implement `src/components/ScoreSparkline.tsx`**

  ```typescript
  import { LineChart, Line, ResponsiveContainer, Tooltip } from 'recharts'

  export function ScoreSparkline({ data }: { data: { computed_at: string; value: number }[] }) {
    return (
      <ResponsiveContainer width="100%" height={40}>
        <LineChart data={data}>
          <Line type="monotone" dataKey="value" stroke="#3b82f6" dot={false} strokeWidth={2} />
          <Tooltip formatter={(v: number) => v.toFixed(3)} />
        </LineChart>
      </ResponsiveContainer>
    )
  }
  ```

- [ ] **Step 7: Implement `src/components/ErrorMessage.tsx`**

  ```typescript
  export function ErrorMessage({ error }: { error: Error | null }) {
    if (!error) return null
    return (
      <div className="rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
        {error.message}
      </div>
    )
  }
  ```

- [ ] **Step 8: Implement `src/components/ConfirmModal.tsx`**

  ```typescript
  interface Props { title: string; message: string; onConfirm: () => void; onCancel: () => void }

  export function ConfirmModal({ title, message, onConfirm, onCancel }: Props) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
        <div className="w-full max-w-sm rounded-lg bg-white p-6 shadow-xl">
          <h2 className="mb-2 text-lg font-semibold">{title}</h2>
          <p className="mb-6 text-sm text-gray-600">{message}</p>
          <div className="flex justify-end gap-3">
            <button onClick={onCancel} className="rounded px-4 py-2 text-sm text-gray-600 hover:bg-gray-100">
              Cancel
            </button>
            <button onClick={onConfirm} className="rounded bg-red-600 px-4 py-2 text-sm text-white hover:bg-red-700">
              Confirm
            </button>
          </div>
        </div>
      </div>
    )
  }
  ```

- [ ] **Step 9: Implement `src/components/Layout.tsx`**

  Sidebar with NavLink entries for all 11 pages + tenant name from auth store in topbar + logout button (`userManager.signoutRedirect()`). Content area renders `<Outlet />`.

  ```typescript
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
  ```

- [ ] **Step 10: Update `src/router.tsx`** — wrap AuthGuard children in `<Layout>`

  ```typescript
  import { createBrowserRouter } from 'react-router-dom'
  import { AuthGuard } from './auth/AuthGuard'
  import { Callback } from './auth/Callback'
  import { Layout } from './components/Layout'

  export const router = createBrowserRouter([
    { path: '/callback', element: <Callback /> },
    {
      element: <AuthGuard />,
      children: [
        {
          element: <Layout />,
          children: [
            { path: '/', element: <div>Dashboard</div> },
            { path: '/assets', element: <div>Assets</div> },
            { path: '/scores', element: <div>Scores</div> },
            { path: '/exposure', element: <div>Exposure</div> },
            { path: '/analysis', element: <div>Analysis</div> },
            { path: '/cases', element: <div>Cases</div> },
            { path: '/actors', element: <div>Actors</div> },
            { path: '/campaigns', element: <div>Campaigns</div> },
            { path: '/observables', element: <div>Observables</div> },
            { path: '/dark-web', element: <div>DarkWeb</div> },
            { path: '/reports', element: <div>Reports</div> },
          ],
        },
      ],
    },
  ])
  ```

- [ ] **Step 11: Run — expect PASS**

  ```bash
  npm test tests/components/
  ```

- [ ] **Step 12: Commit**

  ```bash
  git add frontend/src/components/ frontend/src/router.tsx
  git commit -m "feat: layout shell and shared UI components (DataTable, badges, sparkline, modals)

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 5: Core Pages (Dashboard, Assets, Scores, Exposure, Analysis)

**Files:**
- Create: `frontend/src/api/hooks/useDashboard.ts`
- Create: `frontend/src/api/hooks/useAssets.ts`
- Create: `frontend/src/api/hooks/useScores.ts`
- Create: `frontend/src/api/hooks/useExposure.ts`
- Create: `frontend/src/pages/Dashboard.tsx`
- Create: `frontend/src/pages/Assets.tsx`
- Create: `frontend/src/pages/Scores.tsx`
- Create: `frontend/src/pages/Exposure.tsx`
- Create: `frontend/src/pages/Analysis.tsx`

**Interfaces:**
- Produces: 5 working pages; Exposure PATCH uses optimistic update + rollback; mutation buttons hidden for viewer

- [ ] **Step 1: Write failing tests**

  ```typescript
  // tests/pages/Dashboard.test.tsx
  import { render, screen } from '@testing-library/react'
  import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
  import { vi } from 'vitest'

  vi.mock('@/auth/store', () => ({
    useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: () => true }),
  }))
  vi.mock('@/api/hooks/useDashboard', () => ({
    useDashboard: () => ({
      data: {
        open_cases: 3,
        critical_scores: 1,
        active_exposures: 7,
        recent_events: [],
        scores_by_level: [{ level: 'high', count: 2 }],
      },
      isLoading: false,
      error: null,
    }),
  }))

  import { Dashboard } from '@/pages/Dashboard'

  test('shows KPI counts', () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Dashboard tenantId="t1" />
      </QueryClientProvider>,
    )
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument()
  })
  ```

  ```typescript
  // tests/pages/Exposure.test.tsx
  import { render, screen } from '@testing-library/react'
  import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
  import { vi } from 'vitest'

  const mockHasRole = vi.fn()
  vi.mock('@/auth/store', () => ({
    useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
  }))
  vi.mock('@/api/hooks/useExposure', () => ({
    useExposure: () => ({
      data: { items: [{ id: 'e1', status: 'active', epss_score: 0.42, updated_at: '' }], total: 1 },
      isLoading: false,
    }),
  }))

  import { Exposure } from '@/pages/Exposure'

  test('resolve button visible for analyst', () => {
    mockHasRole.mockImplementation((r: string) => ['analyst'].includes(r))
    render(<QueryClientProvider client={new QueryClient()}><Exposure tenantId="t1" /></QueryClientProvider>)
    expect(screen.getAllByRole('button', { name: /resolve/i }).length).toBeGreaterThan(0)
  })

  test('resolve button hidden for viewer', () => {
    mockHasRole.mockReturnValue(false)
    render(<QueryClientProvider client={new QueryClient()}><Exposure tenantId="t1" /></QueryClientProvider>)
    expect(screen.queryByRole('button', { name: /resolve/i })).not.toBeInTheDocument()
  })
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement TanStack Query hooks**

  ```typescript
  // src/api/hooks/useDashboard.ts
  import { useQuery } from '@tanstack/react-query'
  import { apiGet } from '@/api/client'
  import { useAuthStore } from '@/auth/store'
  import type { DashboardData } from '@/api/types'

  export function useDashboard(tenantId: string) {
    const { user } = useAuthStore()
    return useQuery({
      queryKey: ['dashboard', tenantId],
      queryFn: () =>
        apiGet<DashboardData>(`/api/v1/tenants/${tenantId}/dashboard`, user?.access_token),
      enabled: !!user && !!tenantId,
    })
  }
  ```

  ```typescript
  // src/api/hooks/useAssets.ts
  import { useQuery } from '@tanstack/react-query'
  import { apiGet } from '@/api/client'
  import { useAuthStore } from '@/auth/store'
  import type { Paginated, Asset } from '@/api/types'

  export function useAssets(tenantId: string, page = 1, size = 50) {
    const { user } = useAuthStore()
    return useQuery({
      queryKey: ['assets', tenantId, page],
      queryFn: () =>
        apiGet<Paginated<Asset>>(
          `/api/v1/tenants/${tenantId}/assets?page=${page}&size=${size}`,
          user?.access_token,
        ),
      enabled: !!user && !!tenantId,
    })
  }
  ```

  ```typescript
  // src/api/hooks/useScores.ts
  import { useQuery } from '@tanstack/react-query'
  import { apiGet } from '@/api/client'
  import { useAuthStore } from '@/auth/store'
  import type { Paginated, Score } from '@/api/types'

  export function useScores(tenantId: string) {
    const { user } = useAuthStore()
    return useQuery({
      queryKey: ['scores', tenantId],
      queryFn: () =>
        apiGet<Paginated<Score>>(`/api/v1/tenants/${tenantId}/scores`, user?.access_token),
      enabled: !!user && !!tenantId,
    })
  }
  ```

  ```typescript
  // src/api/hooks/useExposure.ts
  import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
  import { apiGet, apiPatch } from '@/api/client'
  import { useAuthStore } from '@/auth/store'
  import type { Paginated, ExposureMatch } from '@/api/types'

  export function useExposure(tenantId: string, page = 1, size = 50) {
    const { user } = useAuthStore()
    return useQuery({
      queryKey: ['exposure', tenantId, page],
      queryFn: () =>
        apiGet<Paginated<ExposureMatch>>(
          `/api/v1/tenants/${tenantId}/exposure-matches?page=${page}&size=${size}`,
          user?.access_token,
        ),
      enabled: !!user && !!tenantId,
    })
  }

  export function usePatchExposure(tenantId: string) {
    const { user } = useAuthStore()
    const queryClient = useQueryClient()
    return useMutation({
      mutationFn: ({ id, status }: { id: string; status: string }) =>
        apiPatch(`/api/v1/exposure-matches/${id}`, { status }, user?.access_token),
      onMutate: async ({ id, status }) => {
        await queryClient.cancelQueries({ queryKey: ['exposure', tenantId] })
        const prev = queryClient.getQueryData(['exposure', tenantId, 1])
        queryClient.setQueryData(['exposure', tenantId, 1], (old: Paginated<ExposureMatch> | undefined) =>
          old
            ? { ...old, items: old.items.map((e) => (e.id === id ? { ...e, status } : e)) }
            : old,
        )
        return { prev }
      },
      onError: (_err, _vars, ctx) => {
        queryClient.setQueryData(['exposure', tenantId, 1], ctx?.prev)
      },
      onSettled: () => queryClient.invalidateQueries({ queryKey: ['exposure', tenantId] }),
    })
  }
  ```

- [ ] **Step 4: Implement `src/pages/Dashboard.tsx`**

  4 KPI stat cards (open_cases, critical_scores, active_exposures, recent event count) + Recharts BarChart for scores_by_level + recent_events table (rule_name, created_at, is_active badge).

- [ ] **Step 5: Implement `src/pages/Assets.tsx`**

  DataTable<Asset>: hostname, ip, created_at. Client-side filter by hostname input.

- [ ] **Step 6: Implement `src/pages/Scores.tsx`**

  DataTable<Score>: asset_id (truncated), score_type, value (2 dp), level (RiskLevelBadge), computed_at. ScoreSparkline per asset (group by asset_id).

- [ ] **Step 7: Implement `src/pages/Exposure.tsx`**

  DataTable<ExposureMatch>: status (badge), epss_score, updated_at. PATCH resolve/false_positive button visible only when `hasRole('analyst') || hasRole('tenant_admin') || hasRole('super_admin')`. Uses `usePatchExposure` with optimistic update.

- [ ] **Step 8: Implement `src/pages/Analysis.tsx`**

  DataTable<CorrelationEvent>: rule_name, s_context (2 dp), is_active (green/red chip), resolved_at, created_at. Filter toggle: "Active only".

- [ ] **Step 9: Update `src/router.tsx`** with real page imports.

- [ ] **Step 10: Run — expect PASS**

  ```bash
  npm test tests/pages/
  ```

- [ ] **Step 11: Commit**

  ```bash
  git add frontend/src/api/hooks/ frontend/src/pages/Dashboard.tsx frontend/src/pages/Assets.tsx frontend/src/pages/Scores.tsx frontend/src/pages/Exposure.tsx frontend/src/pages/Analysis.tsx
  git commit -m "feat: core pages (dashboard, assets, scores, exposure, analysis)

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 6: Cases + Identities Pages

**Files:**
- Create: `frontend/src/api/hooks/useCases.ts`
- Create: `frontend/src/pages/Cases.tsx`

**Interfaces:**
- Produces: Full CRUD cases table; create/edit slide-over modal for analyst+; viewer sees read-only table; delete with ConfirmModal for tenant_admin/super_admin only

- [ ] **Step 1: Write failing tests**

  ```typescript
  // tests/pages/Cases.test.tsx
  import { render, screen } from '@testing-library/react'
  import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
  import { vi } from 'vitest'

  const mockHasRole = vi.fn()
  vi.mock('@/auth/store', () => ({
    useAuthStore: () => ({ user: { access_token: 'tok' }, hasRole: mockHasRole }),
  }))
  vi.mock('@/api/hooks/useCases', () => ({
    useCases: () => ({
      data: {
        items: [
          { id: 'c1', title: 'Test Case Alpha', status: 'open', severity: 'high', created_at: '' },
          { id: 'c2', title: 'Test Case Beta', status: 'closed', severity: 'low', created_at: '' },
        ],
        total: 2,
      },
      isLoading: false,
    }),
    useCreateCase: () => ({ mutate: vi.fn(), isPending: false }),
    useUpdateCase: () => ({ mutate: vi.fn(), isPending: false }),
    useDeleteCase: () => ({ mutate: vi.fn(), isPending: false }),
  }))

  import { Cases } from '@/pages/Cases'

  test('renders case rows', () => {
    mockHasRole.mockReturnValue(false)
    render(<QueryClientProvider client={new QueryClient()}><Cases tenantId="t1" /></QueryClientProvider>)
    expect(screen.getByText('Test Case Alpha')).toBeInTheDocument()
    expect(screen.getByText('Test Case Beta')).toBeInTheDocument()
  })

  test('New Case button hidden for viewer', () => {
    mockHasRole.mockReturnValue(false)
    render(<QueryClientProvider client={new QueryClient()}><Cases tenantId="t1" /></QueryClientProvider>)
    expect(screen.queryByRole('button', { name: /new case/i })).not.toBeInTheDocument()
  })

  test('New Case button visible for analyst', () => {
    mockHasRole.mockImplementation((r: string) => r === 'analyst')
    render(<QueryClientProvider client={new QueryClient()}><Cases tenantId="t1" /></QueryClientProvider>)
    expect(screen.getByRole('button', { name: /new case/i })).toBeInTheDocument()
  })
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `src/api/hooks/useCases.ts`**

  ```typescript
  import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
  import { apiGet, apiPost, apiPatch, apiDelete } from '@/api/client'
  import { useAuthStore } from '@/auth/store'
  import type { Paginated, Case } from '@/api/types'

  const BASE = (tid: string) => `/api/v1/tenants/${tid}/cases`

  export function useCases(tenantId: string) {
    const { user } = useAuthStore()
    return useQuery({
      queryKey: ['cases', tenantId],
      queryFn: () => apiGet<Paginated<Case>>(BASE(tenantId), user?.access_token),
      enabled: !!user && !!tenantId,
    })
  }

  export function useCreateCase(tenantId: string) {
    const { user } = useAuthStore()
    const qc = useQueryClient()
    return useMutation({
      mutationFn: (body: { title: string; description?: string; severity: string }) =>
        apiPost<Case>(BASE(tenantId), body, user?.access_token),
      onSuccess: () => qc.invalidateQueries({ queryKey: ['cases', tenantId] }),
    })
  }

  export function useUpdateCase(tenantId: string) {
    const { user } = useAuthStore()
    const qc = useQueryClient()
    return useMutation({
      mutationFn: ({ id, ...body }: { id: string; title?: string; status?: string; severity?: string }) =>
        apiPatch<Case>(`${BASE(tenantId)}/${id}`, body, user?.access_token),
      onSuccess: () => qc.invalidateQueries({ queryKey: ['cases', tenantId] }),
    })
  }

  export function useDeleteCase(tenantId: string) {
    const { user } = useAuthStore()
    const qc = useQueryClient()
    return useMutation({
      mutationFn: (id: string) => apiDelete(`${BASE(tenantId)}/${id}`, user?.access_token),
      onSuccess: () => qc.invalidateQueries({ queryKey: ['cases', tenantId] }),
    })
  }
  ```

- [ ] **Step 4: Implement `src/pages/Cases.tsx`**

  DataTable<Case>: title, status (badge), severity (SeverityBadge), created_at.
  "New Case" button (top-right) → modal form (title, description textarea, severity select) visible for `analyst`/`tenant_admin`/`super_admin`.
  Row click → edit modal (pre-filled, status + severity editable).
  Delete button in row → ConfirmModal — visible for `tenant_admin`/`super_admin` only.
  All mutations go through `useCreateCase`, `useUpdateCase`, `useDeleteCase` hooks.

- [ ] **Step 5: Run — expect PASS**

  ```bash
  npm test tests/pages/Cases.test.tsx
  ```

- [ ] **Step 6: Commit**

  ```bash
  git add frontend/src/api/hooks/useCases.ts frontend/src/pages/Cases.tsx
  git commit -m "feat: cases page with full CRUD and RBAC-gated actions

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 7: CTI Catalog + Reports Pages

**Files:**
- Create: `frontend/src/api/hooks/useActors.ts`
- Create: `frontend/src/api/hooks/useCampaigns.ts`
- Create: `frontend/src/api/hooks/useIndicators.ts`
- Create: `frontend/src/api/hooks/useObservations.ts`
- Create: `frontend/src/api/hooks/useReports.ts`
- Create: `frontend/src/pages/Actors.tsx`
- Create: `frontend/src/pages/Campaigns.tsx`
- Create: `frontend/src/pages/Observables.tsx`
- Create: `frontend/src/pages/DarkWeb.tsx`
- Create: `frontend/src/pages/Reports.tsx`

**Interfaces:**
- Produces: 5 read-mostly pages; Reports shows Recharts LineChart for risk trend; DarkWeb filters `observations?event_type=darkweb`

- [ ] **Step 1: Write failing tests**

  ```typescript
  // tests/pages/Actors.test.tsx
  import { render, screen } from '@testing-library/react'
  import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
  import { vi } from 'vitest'

  vi.mock('@/auth/store', () => ({ useAuthStore: () => ({ user: { access_token: 'tok' } }) }))
  vi.mock('@/api/hooks/useActors', () => ({
    useActors: () => ({
      data: { items: [{ id: '1', name: 'APT28', aliases: ['Fancy Bear'], description: null, created_at: '' }], total: 1 },
      isLoading: false,
    }),
  }))

  import { Actors } from '@/pages/Actors'

  test('renders actor name and aliases', () => {
    render(<QueryClientProvider client={new QueryClient()}><Actors /></QueryClientProvider>)
    expect(screen.getByText('APT28')).toBeInTheDocument()
    expect(screen.getByText('Fancy Bear')).toBeInTheDocument()
  })
  ```

  Repeat minimal render tests for Campaigns, Observables, DarkWeb, Reports.

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement hooks**

  ```typescript
  // src/api/hooks/useActors.ts
  import { useQuery } from '@tanstack/react-query'
  import { apiGet } from '@/api/client'
  import { useAuthStore } from '@/auth/store'
  import type { Paginated, ThreatActor } from '@/api/types'

  export function useActors() {
    const { user } = useAuthStore()
    return useQuery({
      queryKey: ['actors'],
      queryFn: () => apiGet<Paginated<ThreatActor>>('/api/v1/threat-actors', user?.access_token),
      enabled: !!user,
    })
  }
  ```

  ```typescript
  // src/api/hooks/useCampaigns.ts
  export function useCampaigns() {
    const { user } = useAuthStore()
    return useQuery({
      queryKey: ['campaigns'],
      queryFn: () => apiGet<Paginated<Campaign>>('/api/v1/campaigns', user?.access_token),
      enabled: !!user,
    })
  }
  ```

  ```typescript
  // src/api/hooks/useIndicators.ts
  export function useIndicators(tenantId: string) {
    const { user } = useAuthStore()
    return useQuery({
      queryKey: ['indicators', tenantId],
      queryFn: () =>
        apiGet<Paginated<Indicator>>(`/api/v1/indicators?tenant_id=${tenantId}`, user?.access_token),
      enabled: !!user && !!tenantId,
    })
  }
  ```

  ```typescript
  // src/api/hooks/useObservations.ts
  export function useObservations(tenantId: string, eventType?: string) {
    const { user } = useAuthStore()
    const qs = eventType ? `?tenant_id=${tenantId}&event_type=${eventType}` : `?tenant_id=${tenantId}`
    return useQuery({
      queryKey: ['observations', tenantId, eventType],
      queryFn: () =>
        apiGet<Paginated<Observation>>(`/api/v1/observations${qs}`, user?.access_token),
      enabled: !!user && !!tenantId,
    })
  }
  ```

  ```typescript
  // src/api/hooks/useReports.ts
  export function useQuickReport(tenantId: string) {
    const { user } = useAuthStore()
    return useQuery({
      queryKey: ['reports', 'quick', tenantId],
      queryFn: () =>
        apiGet<QuickReport>(`/api/v1/reports/quick?tenant_id=${tenantId}`, user?.access_token),
      enabled: !!user && !!tenantId,
    })
  }
  ```

- [ ] **Step 4: Implement `src/pages/Actors.tsx`**

  DataTable<ThreatActor>: name, aliases (join with ", "), description (truncate 80 chars), created_at. Read-only.

- [ ] **Step 5: Implement `src/pages/Campaigns.tsx`**

  DataTable<Campaign>: name, threat_actor_id (display actor name if available via actors cache), description (truncate), created_at. Read-only.

- [ ] **Step 6: Implement `src/pages/Observables.tsx`**

  DataTable<Indicator>: ioc_type (badge), value, confidence (%, 1 dp), created_at. Client-side filter by ioc_type select.

- [ ] **Step 7: Implement `src/pages/DarkWeb.tsx`**

  Uses `useObservations(tenantId, 'darkweb')`. DataTable: event_type, payload.source (string), payload.context (string), created_at. Note: ML classifier is Phase 3; this page shows raw observations only.

- [ ] **Step 8: Implement `src/pages/Reports.tsx`**

  Top: 4 KPI tiles (total_assets, critical_assets, open_cases, top CVE count).
  Risk trend chart:
  ```typescript
  <ResponsiveContainer width="100%" height={200}>
    <LineChart data={report.risk_trend}>
      <XAxis dataKey="date" tick={{ fontSize: 11 }} />
      <YAxis domain={[0, 1]} tick={{ fontSize: 11 }} />
      <Tooltip formatter={(v: number) => v.toFixed(3)} />
      <CartesianGrid strokeDasharray="3 3" />
      <Line type="monotone" dataKey="avg_score" stroke="#ef4444" strokeWidth={2} dot={false} />
    </LineChart>
  </ResponsiveContainer>
  ```
  Top vulnerabilities: DataTable<Vulnerability> with cve_id, cvss_score, epss_score, kev_date_added.

- [ ] **Step 9: Update `src/router.tsx`** — replace all `<div>Page</div>` stubs with real page components.

- [ ] **Step 10: Run all tests — expect PASS**

  ```bash
  npm test
  ```
  Expected: all tests green, 0 failures.

- [ ] **Step 11: Verify build**

  ```bash
  npm run build
  ```
  Expected: exits 0, no TypeScript errors.

- [ ] **Step 12: Commit**

  ```bash
  git add frontend/src/api/hooks/ frontend/src/pages/ frontend/src/router.tsx
  git commit -m "feat: CTI catalog and reports pages (actors, campaigns, observables, dark web, reports)

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

## Integration Verification

After all tasks:

```bash
cd frontend && npm test      # all vitest tests green
cd frontend && npm run build # exits 0
```

Manual smoke test:
1. `docker-compose up api redis keycloak` in `backend/`
2. `cd frontend && npm run dev`
3. Open `http://localhost:5173` → redirects to Keycloak login
4. Login with dev credentials → Dashboard KPI cards visible
5. Navigate Exposure → Resolve button visible for analyst; repeat as viewer → button absent
6. Create a Case as analyst → appears in table
7. Delete case as tenant_admin → ConfirmModal appears, then row removed
8. Navigate Reports → risk trend chart renders
