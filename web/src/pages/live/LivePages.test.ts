import { afterEach, expect, test, vi } from 'vitest'
import type { ControllerACLRule, ControllerCertificate, ControllerNode, ControllerRoute } from '../../lib/control-plane'
import { liveACLRuleLabel, liveCertificateState, liveNodeState, liveRouteMode, liveRouteState } from './LivePages'

afterEach(() => vi.useRealTimers())

test('expired ephemeral enrollment wins over revocation and remains separate from capabilities', () => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-08-12T12:00:00Z'))
  const node: ControllerNode = {
    node_id: '1'.repeat(32),
    network_id: '2'.repeat(32),
    name: 'expired-node',
    enrollment_class: 'ephemeral',
    enabled_capabilities: 16,
    created_at_unix_seconds: 1,
    lease_expires_at_unix_seconds: Math.floor(Date.now() / 1000) - 1,
    revoked_at_unix_seconds: Math.floor(Date.now() / 1000),
  }
  expect(liveNodeState(node)).toEqual({ label: 'Lease expired', tone: 'muted', inactive: true })
  expect(node.enrollment_class).toBe('ephemeral')
  expect(node.enabled_capabilities).toBe(16)
})

test('expired advertisements are non-actionable and every route mode has a truthful label', () => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-08-12T12:00:00Z'))
  const route: ControllerRoute = {
    route_id: '3'.repeat(32),
    network_id: '2'.repeat(32),
    node_id: '1'.repeat(32),
    prefix: '10.0.0.0/24',
    kind: 'subnet',
    mode: 'none',
    metric: 10,
    state: 'advertised',
    valid_until_unix_seconds: Math.floor(Date.now() / 1000) - 1,
    created_at_unix_seconds: 1,
  }
  expect(liveRouteState(route)).toEqual({ label: 'Expired', tone: 'muted', actionable: false })
  expect((['none', 'nat', 'routed'] as const).map(liveRouteMode)).toEqual(['None', 'NAT', 'Routed'])
})

test('ACL fallback labels never overwrite a blank controller description', () => {
  const rule: ControllerACLRule = {
    rule_id: '4'.repeat(32),
    network_id: '2'.repeat(32),
    priority: 9,
    action: 'accept',
    selector: {},
    description: '',
    enabled: true,
    configuration_epoch: 1,
  }
  expect(liveACLRuleLabel(rule)).toBe('Allow rule 9')
  expect(rule.description).toBe('')
})

test('certificate state uses authoritative validity boundaries and revocation', () => {
  const now = 1_700_000_000
  const certificate: ControllerCertificate = {
    certificate_id: '5'.repeat(32),
    network_id: '2'.repeat(32),
    node_id: '1'.repeat(32),
    serial: '01',
    not_before_unix_seconds: now,
    not_after_unix_seconds: now + 60,
    created_at_unix_seconds: now - 60,
  }

  expect(liveCertificateState({ ...certificate, revoked_at_unix_seconds: now - 1 }, now)).toEqual({ label: 'Revoked', tone: 'danger' })
  expect(liveCertificateState({ ...certificate, not_before_unix_seconds: now + 1 }, now)).toEqual({ label: 'Not yet valid', tone: 'warning' })
  expect(liveCertificateState({ ...certificate, not_after_unix_seconds: now }, now)).toEqual({ label: 'Expired', tone: 'muted' })
  expect(liveCertificateState(certificate, now)).toEqual({ label: 'Valid', tone: 'positive' })
})
