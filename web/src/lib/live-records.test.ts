import { afterEach, expect, test, vi } from 'vitest'
import type { ControllerNode, ControllerRoute } from './control-plane'
import { controllerNodes, controllerRoutes, isPendingControllerRoute } from './live-records'

afterEach(() => vi.useRealTimers())

test('expired routes are not pending or approved', () => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-08-11T12:00:00Z'))
  const route: ControllerRoute = {
    route_id: 'route-1',
    network_id: 'network-1',
    node_id: 'node-1',
    prefix: '10.24.0.0/16',
    kind: 'subnet',
    mode: 'none',
    metric: 100,
    state: 'advertised',
    valid_until_unix_seconds: Math.floor(Date.now() / 1000) - 1,
    created_at_unix_seconds: Math.floor(Date.now() / 1000) - 60,
  }

  expect(isPendingControllerRoute(route)).toBe(false)
  expect(controllerRoutes([route], [node('durable')])[0]).toMatchObject({ state: 'Expired', mode: 'None' })
})

test('expired ephemeral nodes keep their enrollment class and inactive state', () => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-08-11T12:00:00Z'))
  const record = node('ephemeral', {
    revoked_at_unix_seconds: Math.floor(Date.now() / 1000),
    lease_expires_at_unix_seconds: Math.floor(Date.now() / 1000) - 1,
  })

  expect(controllerNodes([record])[0]).toMatchObject({
    enrollmentClass: 'Ephemeral user',
    state: 'Lease expired',
    tone: 'muted',
  })
})

function node(enrollmentClass: ControllerNode['enrollment_class'], overrides: Partial<ControllerNode> = {}): ControllerNode {
  return {
    node_id: 'node-1',
    network_id: 'network-1',
    name: 'node-1',
    enabled_capabilities: 0,
    created_at_unix_seconds: 1,
    enrollment_class: enrollmentClass,
    ...overrides,
  }
}
