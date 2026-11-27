import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { TwingatePage } from './TwingatePage'

const request = vi.hoisted(() => vi.fn())
vi.mock('../../lib/control-plane', () => ({
  useControlPlane: () => ({ request, inventory: { networks: [{ network_id: 'lab', name: 'Lab network' }], nodes: [] } }),
}))

const saved = { tenant: 'team', verified_at_unix_seconds: 1_700_000_000 }
const resource = {
  id: 'one', name: 'Registry', kind: 'NetworkResource', active: true, alias: 'registry.internal',
  address: { value: '10.0.0.1' }, remote_network: { name: 'Lab' },
  protocols: { tcp: { policy: 'ALLOW_ALL', ports: [] }, udp: { policy: 'RESTRICTED', ports: [] }, allow_icmp: true },
}
const result = { resources: [resource], total_count: 2, next_cursor: 'cursor' }
const endpoint = '/v1/admin/integrations/twingate'
const disabled = {
  state: 'disabled', gateway_id: null, network_id: null, client_node_id: null,
  resource_id: null, destination: null, tcp_port: null, runtime_available: true, detail: null,
}
const config = { network_id: 'lab', client_node_id: 'dev', resource_id: resource.id, tcp_port: 2222 }
const ready = { ...disabled, ...config, state: 'ready', gateway_id: 'gateway-1', destination: resource.address.value }
const sshCommand = 'ssh -p 2222 USERNAME@10.0.0.1'
const devClient = { network_id: 'lab', node_id: 'dev', name: 'Dev machine', ipv4_address: '100.64.0.2' }

function resourceRow(name: string) {
  return within(screen.getByRole('row', { name: new RegExp(`Select ${name}`) }))
}

function savedResponse(path: string) {
  if (path === endpoint) return Promise.resolve(saved)
  if (path === endpoint + '/gateway') return Promise.resolve(disabled)
  if (path === endpoint + '/resources') return Promise.resolve(result)
  return Promise.reject(new Error(`Unexpected request ${path}`))
}

afterEach(() => { cleanup(); request.mockReset() })

it('opens saved settings on demand and keeps the saved network after a failed replacement', async () => {
  request.mockImplementation((path, options) => options?.method === 'PUT' ? Promise.reject(new Error('Token rejected')) : savedResponse(path))
  render(<MemoryRouter><TwingatePage /></MemoryRouter>)
  const settings = await screen.findByRole('button', { name: 'Connection settings' })
  expect(settings).toHaveAttribute('aria-expanded', 'false')
  expect(screen.getByLabelText('New API token')).not.toBeVisible()
  fireEvent.click(settings)
  expect(settings).toHaveAttribute('aria-expanded', 'true')
  fireEvent.change(screen.getByLabelText('Twingate network'), { target: { value: 'alternate' } })
  fireEvent.change(screen.getByLabelText('New API token'), { target: { value: 'test-token' } })
  fireEvent.click(screen.getByRole('button', { name: 'Test and save' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Token rejected')
  expect(screen.getByRole('heading', { name: 'team.twingate.com' })).toBeVisible()
  expect(screen.getByRole('checkbox', { name: 'Select Registry' })).toBeVisible()
})

it('keeps the last loaded page visible during a pagination failure and retries the failed cursor', async () => {
  let requestedSecondPage = false
  request.mockImplementation((path) => {
    if (path !== endpoint + '/resources?after=cursor') return savedResponse(path)
    if (!requestedSecondPage) {
      requestedSecondPage = true
      return Promise.reject(new Error('Unavailable'))
    }
    return Promise.resolve({ ...result, resources: [{ ...resource, id: 'two', name: 'Analytics' }], next_cursor: null })
  })
  render(<MemoryRouter><TwingatePage /></MemoryRouter>)
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select Registry' }))
  fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Showing the last loaded results from page 1.')
  expect(screen.getByRole('checkbox', { name: 'Select Registry' })).toBeChecked()
  fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
  expect(await screen.findByText('Analytics')).toBeVisible()
  expect(request.mock.calls.at(-1)?.[0]).toMatch(/resources\?after=cursor$/)
  expect(screen.getByText('Page 2')).toBeVisible()
  expect(screen.getByText('1 selected')).toBeVisible()
})

it('enables, reconnects to, edits, and removes SSH access from the resource row', async () => {
  let gateway: { state: string; gateway_id: string | null } = disabled
  let rejected = false
  request.mockImplementation((path, options) => {
    if (path === endpoint) return Promise.resolve(saved)
    if (path === endpoint + '/resources') return Promise.resolve({ ...result, resources: [
      { ...resource, address: { value: `${resource.address.value}/32` }, routing_mode: 'THROUGH_TWINGATE', protocols: { ...resource.protocols, tcp: { policy: 'RESTRICTED', ports: [{ start: 2222, end: 2223 }] } } },
      { ...resource, id: 'two', name: 'Cluster', kind: 'KubernetesResource' },
      { ...resource, id: 'three', name: 'Global network', address: { value: '10.0.0.0/24' } },
    ] })
    if (path === '/v1/admin/networks?limit=100') return Promise.resolve({ networks: [{ network_id: 'lab', name: 'Lab' }] })
    if (path === '/v1/admin/networks/lab/nodes?limit=1000') return Promise.resolve({ nodes: [
      devClient,
      { network_id: 'lab', node_id: 'revoked', name: 'Revoked', ipv4_address: '100.64.0.3', revoked_at_unix_seconds: 1_700_000_000 },
      ...(gateway.state === 'ready' ? [{ network_id: 'lab', node_id: 'owner', name: 'Owner machine', ipv4_address: '100.64.0.4' }] : []),
    ] })
    if (path === endpoint + '/gateway') {
      if (options?.method === 'PUT') {
        if (!rejected) {
          rejected = true
          return Promise.reject(new Error('Provisioning is temporarily unavailable.'))
        }
        gateway = Object.assign({}, disabled, options.body, { state: 'ready', gateway_id: 'gateway-1', destination: resource.address.value })
      }
      if (options?.method === 'DELETE') gateway = disabled
      return Promise.resolve(gateway)
    }
    return Promise.reject(new Error(`Unexpected request ${path}`))
  })

  const mounted = render(<MemoryRouter><TwingatePage /></MemoryRouter>)
  expect(await screen.findByRole('columnheader', { name: 'Laneway access' })).toBeVisible()
  expect(screen.getByRole('heading', { name: 'Twingate bridge' })).toBeVisible()
  fireEvent.click(await resourceRow('Registry').findByRole('button', { name: 'Set up SSH access for Registry' }))
  expect(resourceRow('Cluster').getByText('No bridge access')).toBeVisible()
  expect(resourceRow('Global network').getByText('No bridge access')).toBeVisible()
  expect(resourceRow('Cluster').queryByRole('button', { name: /set up SSH access/i })).not.toBeInTheDocument()
  expect(resourceRow('Global network').queryByRole('button', { name: /set up SSH access/i })).not.toBeInTheDocument()
  const enable = screen.getByRole('button', { name: 'Enable access' })
  const port = screen.getByRole('spinbutton', { name: 'SSH port' })
  await waitFor(() => expect(screen.getByLabelText('Permitted client')).toHaveValue('dev'))
  expect(screen.getByLabelText('Laneway network')).toHaveValue('lab')
  fireEvent.change(port, { target: { value: '22' } })
  expect(enable).toBeDisabled()
  fireEvent.change(port, { target: { value: '2222' } })
  fireEvent.click(enable)
  expect(await screen.findByRole('alert')).toHaveTextContent('Provisioning is temporarily unavailable.')
  expect(screen.getByRole('spinbutton', { name: 'SSH port' })).toHaveValue(2222)
  fireEvent.click(enable)
  expect(await resourceRow('Registry').findByText('Dev machine', { exact: false })).toBeVisible()
  expect(request).toHaveBeenCalledWith(endpoint + '/gateway', { method: 'PUT', body: config, ifMatch: undefined })

  mounted.unmount()
  render(<MemoryRouter><TwingatePage /></MemoryRouter>)
  await screen.findByRole('checkbox', { name: 'Select Registry' })
  const registry = resourceRow('Registry')
  expect(await registry.findByText(/Dev machine/)).toBeVisible()
  expect(registry.getByText(/Lab network/)).toBeVisible()
  const instructions = registry.getByText('Connection instructions')
  expect(registry.getByText(sshCommand)).not.toBeVisible()
  fireEvent.click(instructions)
  expect(registry.getByText(sshCommand)).toBeVisible()
  expect(registry.getByText(/rootless/i)).toBeVisible()
  expect(resourceRow('Cluster').queryByText(sshCommand)).not.toBeInTheDocument()

  fireEvent.click(registry.getByRole('button', { name: 'Edit access' }))
  await screen.findByRole('option', { name: 'Owner machine (100.64.0.4)' })
  expect(screen.getByLabelText('Permitted client')).toHaveValue(config.client_node_id)
  fireEvent.change(screen.getByLabelText('Permitted client'), { target: { value: 'owner' } })
  fireEvent.click(screen.getByRole('button', { name: 'Save permitted client' }))
  expect(await registry.findByText(/Owner machine/)).toBeVisible()
  expect(request).toHaveBeenCalledWith(endpoint + '/gateway', {
    method: 'PUT', body: { ...config, client_node_id: 'owner' }, ifMatch: '"gateway-1:dev"',
  })
  fireEvent.click(registry.getByRole('button', { name: 'Remove access' }))
  expect(request.mock.calls.some(([, options]) => options?.method === 'DELETE')).toBe(false)
  fireEvent.click(screen.getByRole('button', { name: 'Confirm removal' }))
  expect(await registry.findByRole('button', { name: 'Set up SSH access for Registry' })).toBeVisible()
  expect(registry.queryByText('Connection instructions')).not.toBeInTheDocument()
  expect(request).toHaveBeenCalledWith(endpoint + '/gateway', { method: 'DELETE', body: undefined, ifMatch: '"gateway-1"' })
})

it('withdraws previously displayed instructions when bridge health becomes unknown', async () => {
  let statusUnavailable = false
  request.mockImplementation((path) => {
    if (path === endpoint + '/gateway') return statusUnavailable
      ? Promise.reject(new Error('Bridge status service unavailable')) : Promise.resolve(ready)
    if (path === '/v1/admin/networks/lab/nodes?limit=1000') return Promise.resolve({ nodes: [devClient] })
    return savedResponse(path)
  })
  render(<MemoryRouter><TwingatePage /></MemoryRouter>)

  await screen.findByRole('checkbox', { name: 'Select Registry' })
  const registry = resourceRow('Registry')
  fireEvent.click(await registry.findByText('Connection instructions'))
  expect(registry.getByText(sshCommand)).toBeVisible()
  statusUnavailable = true
  fireEvent.click(screen.getByRole('button', { name: 'Refresh resources' }))

  expect(await screen.findByRole('alert')).toHaveTextContent('Bridge status service unavailable')
  expect(registry.getByText('Access unknown')).toBeVisible()
  expect(registry.queryByRole('button', { name: /set up SSH access/i })).not.toBeInTheDocument()
  expect(registry.queryByText('Connection instructions')).not.toBeInTheDocument()
})

it.each([
  { state: 'provisioning', runtime_available: true },
  { state: 'degraded', runtime_available: true },
  { state: 'ready', runtime_available: false },
])('hides SSH instructions while configured access is unavailable ($state, runtime=$runtime_available)', async (status) => {
  request.mockImplementation((path) => {
    if (path === endpoint + '/gateway') return Promise.resolve({ ...ready, ...status })
    if (path === '/v1/admin/networks/lab/nodes?limit=1000') return Promise.resolve({ nodes: [devClient] })
    return savedResponse(path)
  })
  render(<MemoryRouter><TwingatePage /></MemoryRouter>)

  await screen.findByRole('checkbox', { name: 'Select Registry' })
  const registry = resourceRow('Registry')
  expect(await registry.findByText(/Dev machine/)).toBeVisible()
  expect(registry.getByText('SSH access unavailable')).toBeVisible()
  expect(registry.queryByText('Connection instructions')).not.toBeInTheDocument()
  expect(registry.queryByText(sshCommand)).not.toBeInTheDocument()
})
