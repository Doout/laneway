import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { groupMapNodes, mapPoint, NodeMap } from './NodeMap'

const { request, hasPermission } = vi.hoisted(() => ({ request: vi.fn(), hasPermission: vi.fn(() => true) }))
vi.mock('../../lib/control-plane', () => ({ useControlPlane: () => ({ request, hasPermission }) }))
const networks = [{ network_id: '1'.repeat(32), name: 'Production', ipv4_pool: '100.96.0.0/16', configuration_epoch: 1, created_at_unix_seconds: 1 }]
const node = { node_id: '2'.repeat(32), network_id: networks[0].network_id, name: 'Toronto gateway', enrollment_class: 'durable' as const, enabled_capabilities: 0, created_at_unix_seconds: 1 }
const location = { node_id: node.node_id, source: 'manual' as const, observed_at_unix_seconds: 1, stale: false, location: { label: 'Toronto', latitude: 43.65, longitude: -79.38, accuracy_km: 0 } }

describe('node map', () => {
  afterEach(() => { cleanup(); vi.clearAllMocks() })
  it('projects coordinates and clusters colocated nodes without mapping unknowns', () => {
    expect(mapPoint(0, 0)).toEqual([360, 180])
    expect(mapPoint(90, -180)).toEqual([0, 0])
    expect(groupMapNodes([{ node, location }, { node: { ...node, node_id: '3'.repeat(32) }, location }, { node }])).toHaveLength(1)
    expect(groupMapNodes([{ node, location }, { node, location }])[0].nodes).toHaveLength(2)
  })
  it('hides inactive nodes, edits a location and returns to automatic', async () => {
    request.mockImplementation(async (path: string, options?: { method?: string }) => {
      if (options?.method) return undefined
      if (path.includes('/nodes?')) return { nodes: [node, { ...node, node_id: '3'.repeat(32), name: 'Retired node', revoked_at_unix_seconds: 1 }] }
      if (path.includes('/node-locations?')) return { node_locations: [location], automatic_enabled: true }
      if (path.includes('/routes?')) return { routes: [] }
      throw new Error(path)
    })
    render(<NodeMap networks={networks} />)
    fireEvent.click(await screen.findByRole('button', { name: /Toronto gateway/ }))
    expect(screen.queryByText('Retired node')).not.toBeInTheDocument()
    expect(screen.getByText('Configured routes do not confirm a live connection.')).toBeVisible()
    fireEvent.change(screen.getByLabelText('Site name'), { target: { value: 'Office' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save location' }))
    await waitFor(() => expect(request).toHaveBeenCalledWith(`/v1/admin/nodes/${node.node_id}/location`, { method: 'PUT', body: { label: 'Office', latitude: 43.65, longitude: -79.38 } }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Use automatic' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Use automatic' }))
    await waitFor(() => expect(request).toHaveBeenCalledWith(`/v1/admin/nodes/${node.node_id}/location`, { method: 'DELETE' }))
  })
  it('reports unavailable data instead of presenting an empty healthy map', async () => {
    request.mockRejectedValue(new Error('Unavailable'))
    render(<NodeMap networks={networks} />)
    expect(await screen.findByText('Could not load Production.')).toBeVisible()
  })
})
