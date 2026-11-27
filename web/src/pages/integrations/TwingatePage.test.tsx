import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { TwingatePage } from './TwingatePage'

const request = vi.hoisted(() => vi.fn())
vi.mock('../../lib/control-plane', () => ({ useControlPlane: () => ({ request }) }))

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

it('prefills a single eligible client, preserves the port after an error, and disables the saved gateway', async () => {
  const config = { network_id: 'lab', client_node_id: 'dev', resource_id: resource.id, tcp_port: 2222 }
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
      { network_id: 'lab', node_id: 'dev', name: 'Dev machine', ipv4_address: '100.64.0.2' },
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
  fireEvent.click(await screen.findByRole('button', { name: 'Set up SSH gateway for Registry' }))
  expect(screen.queryByRole('button', { name: 'Set up SSH gateway for Cluster' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Set up SSH gateway for Global network' })).not.toBeInTheDocument()
  const enable = screen.getByRole('button', { name: 'Enable gateway' })
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
  expect(await screen.findByText('Online')).toBeVisible()
  expect(request).toHaveBeenCalledWith(endpoint + '/gateway', { method: 'PUT', body: config, ifMatch: undefined })

  mounted.unmount()
  render(<MemoryRouter><TwingatePage /></MemoryRouter>)
  expect(await screen.findByText('Online')).toBeVisible()
  expect(screen.getByText('10.0.0.1:2222')).toBeVisible()

  fireEvent.click(screen.getByRole('button', { name: 'Change permitted client' }))
  await screen.findByRole('option', { name: 'Owner machine (100.64.0.4)' })
  expect(screen.getByLabelText('Permitted client')).toHaveValue(config.client_node_id)
  fireEvent.change(screen.getByLabelText('Permitted client'), { target: { value: 'owner' } })
  fireEvent.click(screen.getByRole('button', { name: 'Save permitted client' }))
  expect(await screen.findByText('Owner machine', { exact: true })).toBeVisible()
  expect(request).toHaveBeenCalledWith(endpoint + '/gateway', {
    method: 'PUT', body: { ...config, client_node_id: 'owner' }, ifMatch: '"gateway-1:dev"',
  })
  fireEvent.click(screen.getByRole('button', { name: 'Disable gateway' }))
  fireEvent.click(screen.getByRole('button', { name: 'Confirm disable' }))
  expect(await screen.findByText('Disabled')).toBeVisible()
  expect(request).toHaveBeenCalledWith(endpoint + '/gateway', { method: 'DELETE', body: undefined, ifMatch: '"gateway-1"' })
})
