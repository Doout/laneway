import { describe, expect, it } from 'vitest'
import type { DaemonStatus, DesktopSnapshot } from './contract'
import { connectionPresentation, expiryLabel, failedRefresh, fallbackLabel, readableError, validateSnapshot } from './presentation'

const status = (overrides: Partial<DaemonStatus> = {}): DaemonStatus => ({
  daemon_instance_id: '1'.repeat(32),
  api_revision: 1,
  running: true,
  actor: 'user',
  product_version: '1.0.0',
  control_version: '1',
  packet_version: 1,
  capabilities: 'relay-v1',
  selected_path: 'relay-quic',
  network_id: '0'.repeat(32),
  node_id: '1'.repeat(32),
  name: 'workstation',
  overlay_addresses: ['100.96.0.2/32'],
  selected_routes: ['10.20.0.0/16'],
  interface: 'lane0',
  relay: 'relay.example:4433',
  mtu: 1280,
  exit: {
    enabled: false,
    authorized: false,
    serving: false,
    forwarding_ready: false,
    nat_ready: false,
    forwarded_packets: 0,
    namespace_cleanup_failures: 0,
  },
  controller: {
    candidate_exchange_enabled: true,
    certificate_presented_serial: '01',
    certificate_renewal_needed: false,
    certificate_renew_after_unix_seconds: 0,
    certificate_not_after_unix_seconds: 0,
    identity_lease_expires_at_unix_seconds: 0,
    configuration_lease_valid_until_unix_seconds: 0,
    configuration_lease_expired: false,
  },
  ...overrides,
})

describe('desktop status presentation', () => {
  it('keeps ordinary, expired, and stopped states distinct', () => {
    expect(connectionPresentation(status())).toMatchObject({ label: 'Connected', tone: 'good' })
    expect(connectionPresentation(status({ controller: { ...status().controller, configuration_lease_expired: true } }))).toMatchObject({ label: 'Needs attention', tone: 'warning' })
    expect(connectionPresentation(status({ running: false }))).toMatchObject({ label: 'Disconnected', tone: 'muted' })
  })

  it('describes active carrier and bounded expiries', () => {
    expect(fallbackLabel('relay-tcp')).toBe('TCP fallback')
    expect(fallbackLabel('direct-quic')).toBe('Direct')
    expect(expiryLabel(0)).toBe('Not reported')
    expect(expiryLabel(1, 2_000)).toBe('Expired')
  })

  it('fails closed on a future backend contract', () => {
    expect(() => validateSnapshot({ contract_version: 2 } as unknown as DesktopSnapshot)).toThrow(/not supported/)
  })

  it('turns Unix ownership failures into an actionable boundary', () => {
    expect(readableError(new Error('connect: permission denied'))).toMatch(/another account/)
    expect(readableError(new Error('local daemon socket is not a protected same-user Unix socket'))).toMatch(/another account/)
    expect(readableError(new Error('No such file or directory'))).toMatch(/not running/)
  })

  it('removes stale authority after any failed refresh', () => {
    expect(failedRefresh(new Error('local daemon request timed out'))).toEqual({
      snapshot: undefined,
      error: 'local daemon request timed out',
    })
  })
})
