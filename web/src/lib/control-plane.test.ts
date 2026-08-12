import { describe, expect, it } from 'vitest'
import { administratorPermissions, parseAdministratorSession, parseConsoleBuildMode } from './control-plane'

describe('console build mode', () => {
  it.each(['live', 'demo'] as const)('accepts the explicit %s mode', (mode) => {
    expect(parseConsoleBuildMode(mode)).toBe(mode)
  })

  it.each(['production', '', undefined])('rejects the unsupported %s mode', (mode) => {
    expect(() => parseConsoleBuildMode(mode)).toThrow('Unsupported console build mode')
  })
})

describe('administrator session parsing', () => {
  function session(overrides: Record<string, unknown> = {}) {
    const now = Math.floor(Date.now() / 1000)
    return {
      principal_id: '1'.repeat(32),
      username: 'console-owner',
      role: 'owner',
      permissions: [...administratorPermissions],
      all_networks: true,
      network_ids: [],
      session_id: '2'.repeat(32),
      idle_lifetime_seconds: 1800,
      idle_expires_at_unix_seconds: now + 1800,
      absolute_expires_at_unix_seconds: now + 28_800,
      csrf_token: 'c'.repeat(43),
      ...overrides,
    }
  }

  it('maps the frozen flat DTO without retaining the CSRF token in the public session', () => {
    const parsed = parseAdministratorSession(session())
    expect(parsed.session).toMatchObject({ username: 'console-owner', role: 'owner', idleLifetimeSeconds: 1800 })
    expect(parsed.csrfToken).toBe('c'.repeat(43))
    expect(parsed.session).not.toHaveProperty('csrfToken')
  })

  it.each([
    { permissions: ['unknown.permission'] },
    { permissions: ['network.list', 'network.list'] },
    { all_networks: false, network_ids: ['3'.repeat(32), '3'.repeat(32)] },
    { idle_lifetime_seconds: 59 },
    { idle_expires_at_unix_seconds: 20, absolute_expires_at_unix_seconds: 10 },
  ])('rejects malformed or drifting session authority %#', (overrides) => {
    expect(() => parseAdministratorSession(session(overrides))).toThrow()
  })
})
