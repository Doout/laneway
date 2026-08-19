import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
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
    expect(screen.queryByRole('link', { name: 'Networks' })).not.toBeInTheDocument()
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
    renderPath('/networks')
    await waitFor(() => expect(screen.getByText('Controller returned inventory outside the selected network scope.')).toBeVisible())
    expect(screen.queryByText('foreign-node')).not.toBeInTheDocument()
  })

  it.each([
    {
      page: 'nodes', path: '/networks?view=nodes', permission: 'node.read', inventoryPath: '/nodes?', responseKey: 'nodes',
      records: [
        { node_id: '4'.repeat(32), network_id: networkId, name: 'healthy-node', enabled_capabilities: 0, created_at_unix_seconds: 1_700_000_000, enrollment_class: 'durable' },
        { node_id: '5'.repeat(32), network_id: networkId, name: 'expired-node', enabled_capabilities: 0, created_at_unix_seconds: 1_700_000_000, enrollment_class: 'ephemeral', lease_expires_at_unix_seconds: 1 },
      ],
      visible: 'healthy-node', hidden: 'expired-node', filter: 'Current only',
    },
    {
      page: 'users', path: '/users', permission: 'acl.read', inventoryPath: '/access-subjects', responseKey: 'users',
      records: [
        { user_id: '4'.repeat(32), network_id: networkId, name: 'active-user', enabled: true, created_at_unix_seconds: 1_700_000_000, updated_at_unix_seconds: 1_700_000_000 },
        { user_id: '5'.repeat(32), network_id: networkId, name: 'disabled-user', enabled: false, created_at_unix_seconds: 1_700_000_000, updated_at_unix_seconds: 1_700_000_100 },
      ],
      visible: 'active-user', hidden: 'disabled-user', filter: 'Enabled only',
    },
    {
      page: 'routes', path: '/routes', permission: 'route.read', inventoryPath: '/routes?', responseKey: 'routes',
      records: [
        { route_id: '4'.repeat(32), network_id: networkId, node_id: '6'.repeat(32), prefix: '10.10.0.0/16', kind: 'subnet', mode: 'nat', metric: 100, state: 'approved', created_at_unix_seconds: 1_700_000_000 },
        { route_id: '5'.repeat(32), network_id: networkId, node_id: '6'.repeat(32), prefix: '10.20.0.0/16', kind: 'subnet', mode: 'nat', metric: 100, state: 'withdrawn', created_at_unix_seconds: 1_700_000_000 },
      ],
      visible: '10.10.0.0/16', hidden: '10.20.0.0/16', filter: 'Current only',
    },
    {
      page: 'access rules', path: '/access', permission: 'acl.read', inventoryPath: '/acl-rules?', responseKey: 'acl_rules',
      records: [
        { rule_id: '4'.repeat(32), network_id: networkId, priority: 10, action: 'accept', selector: {}, description: 'Enabled policy', enabled: true, configuration_epoch: 1 },
        { rule_id: '5'.repeat(32), network_id: networkId, priority: 20, action: 'deny', selector: {}, description: 'Disabled policy', enabled: false, configuration_epoch: 1 },
      ],
      visible: 'Enabled policy', hidden: 'Disabled policy', filter: 'Enabled only',
    },
    {
      page: 'relays', path: '/infrastructure', permission: 'relay.read', inventoryPath: '/relays?', responseKey: 'relays',
      records: [
        { relay_id: '4'.repeat(32), network_id: networkId, service_id: '6'.repeat(32), name: 'enabled-relay', endpoint: 'relay-one.example.test:443', enabled: true, created_at_unix_seconds: 1_700_000_000, configuration_epoch: 1 },
        { relay_id: '5'.repeat(32), network_id: networkId, service_id: '7'.repeat(32), name: 'disabled-relay', endpoint: 'relay-two.example.test:443', enabled: false, created_at_unix_seconds: 1_700_000_000, configuration_epoch: 1 },
      ],
      visible: 'enabled-relay', hidden: 'disabled-relay', filter: 'Enabled relays only',
    },
    {
      page: 'certificates', path: '/security', permission: 'certificate.read', inventoryPath: '/certificates?', responseKey: 'certificates',
      records: [
        { certificate_id: '4'.repeat(32), network_id: networkId, node_id: '6'.repeat(32), serial: 'valid-serial', not_before_unix_seconds: 1_700_000_000, not_after_unix_seconds: 4_000_000_000, created_at_unix_seconds: 1_700_000_000 },
        { certificate_id: '5'.repeat(32), network_id: networkId, node_id: '7'.repeat(32), serial: 'expired-serial', not_before_unix_seconds: 1_600_000_000, not_after_unix_seconds: 1_700_000_000, created_at_unix_seconds: 1_600_000_000 },
      ],
      visible: 'valid-serial', hidden: 'expired-serial', filter: 'Valid only',
    },
  ])('shows current $page by default and reveals inactive records on request', async ({ page: pageName, path: initialPath, permission, inventoryPath, responseKey, records, visible, hidden, filter }) => {
    vi.stubEnv('MODE', 'live')
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(response(session(['network.list', permission])))
      if (path.includes('/networks?')) return Promise.resolve(managementResponse({ networks: [{ network_id: networkId, name: 'Scoped network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 }] }))
      if (path.includes(inventoryPath)) return Promise.resolve(managementResponse(inventoryPath === '/access-subjects' ? { users: records, teams: [], memberships: [], grants: [] } : { [responseKey]: records }))
      if (path.includes('/acl-rules?')) return Promise.resolve(managementResponse({ acl_rules: [] }))
      if (path.includes('/access-subjects')) return Promise.resolve(managementResponse({ users: [], teams: [], memberships: [], grants: [] }))
      throw new Error(`Unexpected request ${path}`)
    }))

    renderPath(initialPath)
    expect(await screen.findByText(visible)).toBeVisible()
    expect(screen.queryByText(hidden)).not.toBeInTheDocument()
    expect(screen.getByLabelText('Record visibility')).toHaveValue('current')
    expect(screen.getByRole('option', { name: filter })).toBeInTheDocument()
    if (pageName === 'nodes') {
      expect(screen.getByText('1 of 1 shown')).toBeVisible()
      expect(screen.getByRole('link', { name: 'Nodes' })).toHaveTextContent('1')
    }

    fireEvent.change(screen.getByLabelText('Record visibility'), { target: { value: 'all' } })
    expect(await screen.findByText(hidden)).toBeVisible()
    if (pageName === 'nodes') {
      expect(screen.getByText('2 of 2 shown')).toBeVisible()
      expect(screen.getByText('Lease expired')).toBeVisible()
      expect(screen.getByRole('heading', { name: 'History' })).toBeVisible()
      expect(screen.getByText('1 inactive')).toBeVisible()
      expect(screen.getByRole('link', { name: 'View' })).toHaveAttribute('href', `/nodes/${'5'.repeat(32)}`)
      expect(screen.queryByText('Ephemeral enrollment')).not.toBeInTheDocument()
      expect(screen.getByRole('link', { name: 'Nodes' })).toHaveTextContent('1')
    }
  })

  it('shows an administrator-assigned route as approved without sending it through approval', async () => {
    vi.stubEnv('MODE', 'live')
    const nodeId = '4'.repeat(32)
    const routeId = '5'.repeat(32)
    const route = { route_id: routeId, network_id: networkId, node_id: nodeId, prefix: '10.20.0.0/24', kind: 'subnet', mode: 'nat', metric: 100, state: 'approved', created_at_unix_seconds: 1_700_000_000, approved_at_unix_seconds: 1_700_000_000 }
    let assigned = false
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(response(session(['network.list', 'node.read', 'route.read', 'route.manage'])))
      if (path.includes('/networks?')) return Promise.resolve(managementResponse({ networks: [{ network_id: networkId, name: 'Scoped network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 }] }))
      if (path.includes('/nodes?')) return Promise.resolve(managementResponse({ nodes: [{ node_id: nodeId, network_id: networkId, name: 'Forwarding node', enabled_capabilities: 16, created_at_unix_seconds: 1_700_000_000, enrollment_class: 'durable' }] }))
      if (path.includes('/routes?')) return Promise.resolve(managementResponse({ routes: assigned ? [route] : [] }))
      if (path.endsWith('/routes/assign')) {
        expect(init?.method).toBe('POST')
        assigned = true
        return Promise.resolve(managementResponse(route))
      }
      throw new Error(`Unexpected request ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)

    renderPath('/routes/new')
    fireEvent.change(await screen.findByLabelText('Destination prefix'), { target: { value: route.prefix } })
    fireEvent.click(screen.getByRole('button', { name: 'Assign route' }))

    expect(await screen.findByRole('heading', { name: route.prefix })).toBeVisible()
    expect(screen.getByText('Approved')).toBeVisible()
    expect(screen.queryByRole('heading', { name: 'Approve route' })).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith(`/routes/${routeId}/approve`))).toBe(false)
  })

  it('creates a traffic rule from guided fields without exposing selector JSON', async () => {
    vi.stubEnv('MODE', 'live')
    const ruleId = '6'.repeat(32)
    let created = false
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(response(session(['network.list', 'acl.read', 'acl.manage'])))
      if (path.includes('/networks?')) return Promise.resolve(managementResponse({ networks: [{ network_id: networkId, name: 'Scoped network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 }] }))
      if (path.includes('/acl-rules?')) return Promise.resolve(managementResponse({ acl_rules: created ? [{ rule_id: ruleId, network_id: networkId, priority: 100, action: 'accept', selector: { destination_prefixes: [{ address: 'ChgAAA==', prefix_length: 16 }], ip_protocol: 'IP_PROTOCOL_TCP', destination_ports: [{ first: 443, last: 443 }] }, description: 'Allow production HTTPS', enabled: true, configuration_epoch: 2 }] : [] }))
      if (path.includes('/access-subjects')) return Promise.resolve(managementResponse({ users: [], teams: [], memberships: [], grants: [] }))
      if (path.endsWith(`/networks/${networkId}/acl-rules`)) {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>
        expect(body).toMatchObject({ description: 'Allow production HTTPS', action: 'accept', priority: 100, selector: { destination_prefixes: [{ address: 'ChgAAA==', prefix_length: 16 }], ip_protocol: 'IP_PROTOCOL_TCP', destination_ports: [{ first: 80, last: 80 }, { first: 443, last: 443 }, { first: 8443, last: 8450 }] } })
        created = true
        return Promise.resolve(managementResponse({ rule_id: ruleId }))
      }
      throw new Error(`Unexpected request ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)

    renderPath('/access/new')
    expect(await screen.findByRole('heading', { name: 'Add traffic rule' })).toBeVisible()
    expect(screen.queryByLabelText('Selector JSON')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Rule name'), { target: { value: 'Allow production HTTPS' } })
    fireEvent.change(screen.getByLabelText('IPv4 prefix'), { target: { value: '10.24.0.0/16' } })
    expect(screen.getByLabelText('Port format help')).toBeVisible()
    fireEvent.change(screen.getByLabelText('Destination ports'), { target: { value: '80, 443, 8443-8450' } })
    fireEvent.click(screen.getByRole('checkbox', { name: /Confirm allowed traffic/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Create rule' }))

    expect(await screen.findByRole('heading', { name: 'Allow production HTTPS' })).toBeVisible()
    expect(screen.getByText('TCP · 443')).toBeVisible()
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
    expect(await screen.findByText(`Recovery grant · ${recoveryId.slice(0, 8)}…${recoveryId.slice(-4)}`)).toBeVisible()
    expect(screen.getByText(recoveryId)).toBeVisible()
    expect(screen.getByText('Global')).toBeVisible()
    expect(screen.queryByLabelText('Selected network')).not.toBeInTheDocument()
    const paths = fetchMock.mock.calls.map(([input]) => String(input))
    expect(paths.filter((path) => path.endsWith('/v1/admin/audit?limit=250'))).toHaveLength(1)
    expect(paths.some((path) => /\/networks\/[0-9a-f]{32}\/audit/.test(path))).toBe(false)
  })

  it.each([
    { path: '/nodes/new', field: 'Node name', heading: 'Node token issued', command: /sudo laneway node install .* --token-file \.\/laneway\.code/, userId: '' },
    { path: `/users/${'4'.repeat(32)}/enroll`, field: 'Device name', heading: 'Example User node token issued', command: /laneway connect .* --ephemeral --token-file \.\/laneway\.code/, userId: '4'.repeat(32) },
  ])('renders the canonical one-time enrollment command for $path', async ({ path: initialPath, field, heading, command, userId }) => {
    vi.stubEnv('MODE', 'live')
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(response(session(['network.list', 'enrollment.issue', ...(userId ? ['acl.read'] : [])])))
      if (path.includes('/networks?')) return Promise.resolve(managementResponse({ networks: [{ network_id: networkId, name: 'Scoped network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 }] }))
      if (path.includes('/acl-rules?')) return Promise.resolve(managementResponse({ acl_rules: [] }))
      if (path.includes('/access-subjects')) return Promise.resolve(managementResponse({ users: userId ? [{ user_id: userId, network_id: networkId, name: 'Example User', enabled: true, created_at_unix_seconds: 1_700_000_000, updated_at_unix_seconds: 1_700_000_000 }] : [], teams: [], memberships: [], grants: [] }))
      if (path.endsWith('/enrollment-tokens')) return Promise.resolve(managementResponse({ enrollment_token: 'test-one-time-enrollment-secret' }))
      throw new Error(`Unexpected request ${path}`)
    }))

    renderPath(initialPath)
    fireEvent.change(await screen.findByLabelText(field), { target: { value: 'test enrollment' } })
    fireEvent.click(screen.getByRole('button', { name: 'Issue token' }))

    expect(await screen.findByRole('heading', { name: heading })).toBeVisible()
    expect(screen.getByText(command)).toBeVisible()
  })

  it('reports configured inventory without presenting relay enablement as runtime health', async () => {
    vi.stubEnv('MODE', 'live')
    const nodeId = '4'.repeat(32)
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(response(session(['network.list', 'node.read', 'route.read', 'acl.read', 'relay.read', 'certificate.read'])))
      if (path.includes('/networks?')) return Promise.resolve(managementResponse({ networks: [{ network_id: networkId, name: 'Scoped network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 }] }))
      if (path.includes('/nodes?')) return Promise.resolve(managementResponse({ nodes: [{ node_id: nodeId, network_id: networkId, name: 'configured-node', enabled_capabilities: 0, created_at_unix_seconds: 1_700_000_000, enrollment_class: 'durable' }] }))
      if (path.includes('/routes?')) return Promise.resolve(managementResponse({ routes: [{ route_id: '5'.repeat(32), network_id: networkId, node_id: nodeId, prefix: '10.20.0.0/16', kind: 'subnet', mode: 'nat', metric: 100, state: 'approved', created_at_unix_seconds: 1_700_000_000 }] }))
      if (path.includes('/access-subjects')) return Promise.resolve(managementResponse({ users: [], teams: [], memberships: [], grants: [] }))
      if (path.includes('/acl-rules?')) return Promise.resolve(managementResponse({ acl_rules: [{ rule_id: '6'.repeat(32), network_id: networkId, priority: 100, action: 'accept', selector: {}, description: 'Configured rule', enabled: true, configuration_epoch: 1 }] }))
      if (path.includes('/relays?')) return Promise.resolve(managementResponse({ relays: [{ relay_id: '7'.repeat(32), network_id: networkId, service_id: '8'.repeat(32), name: 'enabled-relay', endpoint: 'relay.example.test:443', enabled: true, created_at_unix_seconds: 1_700_000_000, configuration_epoch: 1 }] }))
      if (path.includes('/certificates?')) return Promise.resolve(managementResponse({ certificates: [] }))
      throw new Error(`Unexpected request ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)

    renderPath('/overview')
    expect(await screen.findByText('Controller inventory')).toBeVisible()
    expect(screen.getByText('current nodes and enabled relays')).toBeVisible()
    expect(screen.getByText('current routes and enabled rules')).toBeVisible()
    expect(screen.getByText('Current nodes')).toBeVisible()
    expect(screen.getByText('Current routes')).toBeVisible()
    expect(screen.queryByText('Online')).not.toBeInTheDocument()
    expect(screen.queryByText('active nodes and relays')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('link', { name: /^Infrastructure$/ }))
    expect(await screen.findByRole('heading', { name: 'Infrastructure' })).toBeVisible()
    expect(screen.getByText('Enabled relays')).toBeVisible()
    expect(screen.getByText('Runtime status')).toBeVisible()
    expect(screen.getByText('Not reported')).toBeVisible()
    expect(screen.getByText('No relay health telemetry')).toBeVisible()
    expect(screen.getByText('Configured')).toBeVisible()
    expect(screen.queryByText('Relays online')).not.toBeInTheDocument()
    expect(screen.queryByText('Coverage')).not.toBeInTheDocument()
  })

  it('marks permission-limited inventory counts as unavailable instead of zero', async () => {
    vi.stubEnv('MODE', 'live')
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(response(session(['network.list'])))
      if (path.includes('/networks?')) return Promise.resolve(managementResponse({ networks: [{ network_id: networkId, name: 'Scoped network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 }] }))
      throw new Error(`Unexpected request ${path}`)
    }))

    renderPath('/overview')
    const overviewSummary = await screen.findByLabelText('Network inventory summary')
    expect(within(overviewSummary).getAllByText('—')).toHaveLength(3)
    expect(within(overviewSummary).getAllByText('Not authorized')).toHaveLength(3)

    fireEvent.click(screen.getByRole('link', { name: /^Infrastructure$/ }))
    expect(await screen.findByText('Relay inventory unavailable')).toBeVisible()
    expect(screen.getByText('This administrator cannot read relay records.')).toBeVisible()
    const infrastructureSummary = screen.getByLabelText('Infrastructure summary')
    expect(within(infrastructureSummary).getByText('Not authorized')).toBeVisible()
  })

  it('keeps node moves and network connections visible but unavailable when the API has no contract', async () => {
    vi.stubEnv('MODE', 'live')
    const secondNetworkId = '5'.repeat(32)
    const nodeId = '4'.repeat(32)
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(response(session(['network.list', 'node.read', 'route.read'], { network_ids: [networkId, secondNetworkId] })))
      if (path.includes('/networks?')) return Promise.resolve(managementResponse({ networks: [
        { network_id: networkId, name: 'First network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 },
        { network_id: secondNetworkId, name: 'Second network', ipv4_pool: '100.65.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1_700_000_000 },
      ] }))
      if (path.includes(`/networks/${networkId}/nodes?`)) return Promise.resolve(managementResponse({ nodes: [{ node_id: nodeId, network_id: networkId, name: 'movable-node', enabled_capabilities: 0, created_at_unix_seconds: 1_700_000_000, enrollment_class: 'durable' }] }))
      if (path.includes(`/networks/${secondNetworkId}/nodes?`)) return Promise.resolve(managementResponse({ nodes: [] }))
      if (path.includes('/routes?')) return Promise.resolve(managementResponse({ routes: [] }))
      throw new Error(`Unexpected request ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)

    renderPath('/networks?view=nodes')
    expect(await screen.findByText('movable-node')).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Move' }))
    expect(screen.getByText('Node reassignment is not available in this controller API.')).toBeVisible()
    expect(screen.getByLabelText('Destination network')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Unavailable' })).toBeDisabled()

    fireEvent.click(screen.getByRole('link', { name: 'Connectivity' }))
    expect(await screen.findByText('Connection data unavailable')).toBeVisible()
    expect(screen.getByText('No connection state reported')).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Connect network' }))
    expect(screen.getByText('Network connection management is not available in this controller API.')).toBeVisible()
    expect(screen.getByLabelText('Destination network')).toBeDisabled()
    expect(screen.getByLabelText('Traffic direction')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Unavailable' })).toBeDisabled()

    const paths = fetchMock.mock.calls.map(([input]) => String(input))
    expect(paths.some((path) => path.includes('/network-connections'))).toBe(false)
    expect(paths.some((path) => path.includes(`/nodes/${nodeId}/move`))).toBe(false)
  })
})
