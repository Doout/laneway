import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { App } from './App'
import { administratorPermissions, ControlPlaneProvider } from './lib/control-plane'

const principalId = '1'.repeat(32)
const sessionId = '2'.repeat(32)
const networkId = '3'.repeat(32)
const csrfToken = 'c'.repeat(43)

function sessionView(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000)
  return {
    principal_id: principalId,
    username: 'console-owner',
    role: 'owner',
    permissions: [...administratorPermissions],
    all_networks: true,
    network_ids: [],
    session_id: sessionId,
    idle_lifetime_seconds: 1800,
    idle_expires_at_unix_seconds: now + 1800,
    absolute_expires_at_unix_seconds: now + 28_800,
    csrf_token: csrfToken,
    ...overrides,
  }
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: status === 204 ? headers : { 'Content-Type': 'application/json', ...headers },
  })
}

function managementResponse(body: unknown, overrides: Record<string, string> = {}) {
  const now = Math.floor(Date.now() / 1000)
  return jsonResponse(body, 200, {
    'X-Laneway-Session-ID': sessionId,
    'X-Laneway-Session-Idle-Expires-At': String(now + 1800),
    'X-Laneway-Session-Absolute-Expires-At': String(now + 28_800),
    ...overrides,
  })
}

function renderApp(path: string) {
  return render(<ControlPlaneProvider><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></ControlPlaneProvider>)
}

describe('Laneway browser sessions', () => {
  afterEach(() => {
    cleanup()
    vi.unstubAllEnvs()
    vi.unstubAllGlobals()
    window.sessionStorage.clear()
    window.localStorage.clear()
  })

  it('keeps deliberate demo mode functional without inventing an authenticated identity', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    renderApp('/sign-in')

    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeVisible()
    expect(screen.getByRole('note', { name: 'Demo data notice' })).toBeVisible()
    expect(screen.queryByLabelText('Signed in administrator')).not.toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('purges every legacy auth value before the first live request', async () => {
    vi.stubEnv('MODE', 'live')
    for (const storage of [window.localStorage, window.sessionStorage]) {
      storage.setItem('laneway-console-admin-token', 'legacy-secret')
      storage.setItem('laneway-console-operator', 'Legacy Name')
    }
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      expect(window.localStorage.getItem('laneway-console-admin-token')).toBeNull()
      expect(window.sessionStorage.getItem('laneway-console-admin-token')).toBeNull()
      expect(window.localStorage.getItem('laneway-console-operator')).toBeNull()
      expect(window.sessionStorage.getItem('laneway-console-operator')).toBeNull()
      return Promise.resolve(String(input).endsWith('/session')
        ? jsonResponse({ error: 'unauthorized' }, 401)
        : jsonResponse({ state: 'sign_in' }))
    })
    vi.stubGlobal('fetch', fetchMock)

    renderApp('/overview')

    expect(await screen.findByRole('heading', { name: 'Sign in to Laneway' })).toBeVisible()
    expect(screen.queryByText('Legacy Name')).not.toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('shows control-node setup instructions without a browser grant or token form', async () => {
    vi.stubEnv('MODE', 'live')
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => Promise.resolve(
      String(input).endsWith('/session')
        ? jsonResponse({ error: 'unauthorized' }, 401)
        : jsonResponse({ state: 'bootstrap_required' }),
    )))

    renderApp('/setup')

    expect(await screen.findByRole('heading', { name: 'Setup required' })).toBeVisible()
    expect(screen.getByText('Complete administrator setup on the control node.')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeEnabled()
    expect(screen.queryByLabelText(/token|operator|controller address/i)).not.toBeInTheDocument()
  })

  it('signs in with a password and safely restores the original deep link', async () => {
    vi.stubEnv('MODE', 'live')
    const calls: Array<{ path: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      calls.push({ path, init })
      if (path.endsWith('/auth/session')) return Promise.resolve(jsonResponse({ error: 'unauthorized' }, 401))
      if (path.endsWith('/auth/state')) return Promise.resolve(jsonResponse({ state: 'sign_in' }))
      if (path.endsWith('/auth/login')) return Promise.resolve(jsonResponse(sessionView()))
      if (path.includes('/v1/admin/networks?')) return Promise.resolve(managementResponse({ networks: [{ network_id: networkId, name: 'Private network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 }] }))
      if (path.includes('/nodes?')) return Promise.resolve(managementResponse({ nodes: [] }))
      if (path.includes('/access-subjects')) return Promise.resolve(managementResponse({ users: [], teams: [], memberships: [], grants: [] }))
      if (path.includes('/routes?')) return Promise.resolve(managementResponse({ routes: [] }))
      if (path.includes('/acl-rules?')) return Promise.resolve(managementResponse({ acl_rules: [] }))
      if (path.includes('/relays?')) return Promise.resolve(managementResponse({ relays: [] }))
      if (path.includes('/certificates?')) return Promise.resolve(managementResponse({ certificates: [] }))
      if (path.includes('/audit?')) return Promise.resolve(managementResponse({ events: [] }))
      throw new Error(`Unexpected request ${path}`)
    }))

    renderApp('/routes?state=pending#queue')
    expect(await screen.findByRole('heading', { name: 'Sign in to Laneway' })).toBeVisible()
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'console-owner' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'a sufficiently long password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('heading', { name: 'Routes' })).toBeVisible()
    expect(screen.getByLabelText('Signed in administrator')).toHaveTextContent('console-owner')
    const login = calls.find((call) => call.path.endsWith('/auth/login'))
    expect(login?.init?.credentials).toBe('same-origin')
    expect(new Headers(login?.init?.headers).has('Authorization')).toBe(false)
    expect(JSON.parse(String(login?.init?.body))).toEqual({ username: 'console-owner', password: 'a sufficiently long password' })
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
  })

  it('retains an authenticated session when logout cannot be confirmed, then clears it after success', async () => {
    vi.stubEnv('MODE', 'live')
    let logoutAttempts = 0
    const calls: Array<{ path: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      calls.push({ path, init })
      if (path.endsWith('/auth/session')) return Promise.resolve(jsonResponse(sessionView()))
      if (path.includes('/v1/admin/networks?')) return Promise.resolve(managementResponse({ networks: [] }))
      if (path.endsWith('/v1/admin/audit?limit=250')) return Promise.resolve(managementResponse({ events: [] }))
      if (path.endsWith('/auth/logout')) {
        logoutAttempts += 1
        return Promise.resolve(logoutAttempts === 1 ? jsonResponse({ error: 'temporarily unavailable' }, 503) : jsonResponse(null, 204))
      }
      throw new Error(`Unexpected request ${path}`)
    }))

    renderApp('/overview')
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('temporarily unavailable')
    expect(screen.getByRole('heading', { name: 'Overview' })).toBeVisible()
    expect(screen.getByLabelText('Signed in administrator')).toHaveTextContent('console-owner')

    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('heading', { name: 'Sign in to Laneway' })).toBeVisible()
    const logoutCalls = calls.filter((call) => call.path.endsWith('/auth/logout'))
    expect(logoutCalls).toHaveLength(2)
    expect(new Headers(logoutCalls[0].init?.headers).get('X-Laneway-CSRF')).toBe(csrfToken)
    expect(new Headers(logoutCalls[0].init?.headers).has('Authorization')).toBe(false)
    expect(calls.filter((call) => call.path.endsWith('/v1/admin/audit?limit=250'))).toHaveLength(1)
  })

  it('filters inventory requests and mutating actions using server permissions', async () => {
    vi.stubEnv('MODE', 'live')
    const requested: string[] = []
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      requested.push(path)
      if (path.endsWith('/auth/session')) return Promise.resolve(jsonResponse(sessionView({
        username: 'route-auditor',
        role: 'auditor',
        permissions: ['network.list', 'route.read'],
        all_networks: false,
        network_ids: [networkId],
      })))
      if (path.includes('/v1/admin/networks?')) return Promise.resolve(managementResponse({ networks: [{ network_id: networkId, name: 'Private network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 }] }))
      if (path.includes('/routes?')) return Promise.resolve(managementResponse({ routes: [] }))
      throw new Error(`Unexpected request ${path}`)
    }))

    renderApp('/routes')

    expect(await screen.findByRole('heading', { name: 'Routes' })).toBeVisible()
    expect(screen.queryByRole('link', { name: /Create route/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Nodes' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Security' })).not.toBeInTheDocument()
    await waitFor(() => expect(requested.some((path) => path.includes('/routes?'))).toBe(true))
    expect(requested.some((path) => path.includes('/nodes?'))).toBe(false)
    expect(requested.some((path) => path.includes('/certificates?'))).toBe(false)
  })

  it('fails closed when the restored session view is malformed', async () => {
    vi.stubEnv('MODE', 'live')
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(jsonResponse(sessionView({ permissions: ['unknown.permission'] })))))

    renderApp('/overview')

    expect(await screen.findByRole('heading', { name: 'Controller unavailable' })).toBeVisible()
    expect(screen.getByRole('alert')).toHaveTextContent('Invalid administrator session response')
    expect(screen.queryByText('console-owner')).not.toBeInTheDocument()
  })
})
