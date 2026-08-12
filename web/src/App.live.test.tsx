import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { App } from './App.live'
import { ControlPlaneProvider } from './lib/control-plane'

const networkId = '3'.repeat(32)
function response(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }) }
function session(permissions: string[], overrides: Record<string, unknown> = {}) { const now = Math.floor(Date.now() / 1000); return { principal_id: '1'.repeat(32), username: 'auditor', role: 'auditor', permissions, all_networks: false, network_ids: [networkId], session_id: '2'.repeat(32), idle_lifetime_seconds: 1800, idle_expires_at_unix_seconds: now + 1800, absolute_expires_at_unix_seconds: now + 3600, csrf_token: 'c'.repeat(43), ...overrides } }
function managementResponse(body: unknown) { const now = Math.floor(Date.now() / 1000); return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json', 'X-Laneway-Session-ID': '2'.repeat(32), 'X-Laneway-Session-Idle-Expires-At': String(now + 1800), 'X-Laneway-Session-Absolute-Expires-At': String(now + 3600) } }) }
function renderPath(path: string) { return render(<ControlPlaneProvider><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></ControlPlaneProvider>) }

describe('shipped live application authorization', () => {
  afterEach(() => { cleanup(); vi.unstubAllEnvs(); vi.unstubAllGlobals() })

  it('denies a direct mutation route and omits unrelated navigation', async () => {
    vi.stubEnv('MODE', 'live')
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(response(session(['network.list', 'route.read'])))
      if (path.includes('/networks?')) return Promise.resolve(managementResponse({ networks: [{ network_id: networkId, name: 'Scoped network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 }] }))
      if (path.includes('/routes?')) return Promise.resolve(managementResponse({ routes: [] }))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderPath('/routes/new')
    expect(await screen.findByRole('heading', { name: 'Access denied' })).toBeVisible()
    expect(screen.queryByRole('link', { name: 'Nodes' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Security' })).not.toBeInTheDocument()
  })

  it('rejects an inventory record whose network provenance differs from the selected scope', async () => {
    vi.stubEnv('MODE', 'live')
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(response(session(['network.list', 'node.read'])))
      if (path.includes('/networks?')) return Promise.resolve(managementResponse({ networks: [{ network_id: networkId, name: 'Scoped network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 }] }))
      if (path.includes('/nodes?')) return Promise.resolve(managementResponse({ nodes: [{ node_id: '4'.repeat(32), network_id: '5'.repeat(32), name: 'foreign-node', enabled_capabilities: 0, created_at_unix_seconds: 1_700_000_000, enrollment_class: 'durable' }] }))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderPath('/nodes')
    await waitFor(() => expect(screen.getByText('Controller returned inventory outside the selected network scope.')).toBeVisible())
    expect(screen.queryByText('foreign-node')).not.toBeInTheDocument()
  })

  it('loads the owner global audit stream once and renders recovery actors without selecting a network', async () => {
    vi.stubEnv('MODE', 'live')
    const secondNetworkId = '5'.repeat(32)
    const recoveryId = '6'.repeat(32)
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(response(session(['network.list', 'network.read', 'audit.read_global'], { username: 'owner', role: 'owner', all_networks: true, network_ids: [] })))
      if (path.includes('/networks?')) return Promise.resolve(managementResponse({ networks: [
        { network_id: networkId, name: 'First network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 },
        { network_id: secondNetworkId, name: 'Second network', ipv4_pool: '100.65.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 },
      ] }))
      if (path.endsWith('/v1/admin/audit?limit=250')) return Promise.resolve(managementResponse({ events: [{ event_id: '7'.repeat(32), actor_kind: 'recovery_grant', actor_id: recoveryId, action: 'administrator.recover', target_type: 'administrator_session', details: {}, created_at_unix_seconds: 1_700_000_100 }] }))
      throw new Error(`Unexpected request ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)
    renderPath('/audit')
    expect(await screen.findByText(`Recovery grant ${recoveryId}`)).toBeVisible()
    expect(screen.getByText('Global')).toBeVisible()
    expect(screen.getByLabelText('Selected network')).toBeVisible()
    const paths = fetchMock.mock.calls.map(([input]) => String(input))
    expect(paths.filter((path) => path.endsWith('/v1/admin/audit?limit=250'))).toHaveLength(1)
    expect(paths.some((path) => /\/networks\/[0-9a-f]{32}\/audit/.test(path))).toBe(false)
  })

  it.each([
    { path: '/nodes/new', field: 'Node name', heading: 'Node token issued', command: /sudo laneway node install .* --token-file \.\/laneway\.code/ },
    { path: '/users/new', field: 'Requested node name', heading: 'User token issued', command: /laneway connect .* --ephemeral --token-file \.\/laneway\.code/ },
  ])('renders the canonical one-time enrollment command for $path', async ({ path: initialPath, field, heading, command }) => {
    vi.stubEnv('MODE', 'live')
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(response(session(['network.list', 'enrollment.issue'])))
      if (path.includes('/networks?')) return Promise.resolve(managementResponse({ networks: [{ network_id: networkId, name: 'Scoped network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 }] }))
      if (path.endsWith('/enrollment-tokens')) return Promise.resolve(managementResponse({ enrollment_token: 'test-one-time-enrollment-secret' }))
      throw new Error(`Unexpected request ${path}`)
    }))

    renderPath(initialPath)
    fireEvent.change(await screen.findByLabelText(field), { target: { value: 'test enrollment' } })
    fireEvent.click(screen.getByRole('button', { name: 'Issue token' }))

    expect(await screen.findByRole('heading', { name: heading })).toBeVisible()
    expect(screen.getByText(command)).toBeVisible()
  })
})
