import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { ControlPlaneProvider } from '../../lib/control-plane'
import { AuditPage, formatControllerAuditActor } from './AuditPage'

describe('audit split inspector', () => {
  it('moves event identity into the inspector and supports empty search recovery', async () => {
    const user = userEvent.setup()
    render(<MemoryRouter><ControlPlaneProvider><AuditPage /></ControlPlaneProvider></MemoryRouter>)
    await user.click(screen.getByRole('button', { name: /Relay probe failed/i }))
    expect(screen.getByRole('heading', { name: 'Relay probe failed' })).toBeVisible()
    await user.type(screen.getByRole('searchbox', { name: 'Search audit events' }), 'no-such-audit-event')
    expect(screen.getByRole('heading', { name: 'No matching events' })).toBeVisible()
  })

  it.each([
    [{ actor_kind: 'system' as const }, 'System'],
    [{ actor_kind: 'administrator' as const, actor_id: '1'.repeat(32) }, `Administrator ${'1'.repeat(32)}`],
    [{ actor_kind: 'service_principal' as const, actor_id: '2'.repeat(32) }, `Service principal ${'2'.repeat(32)}`],
    [{ actor_kind: 'recovery_grant' as const, actor_id: '4'.repeat(32) }, `Recovery grant ${'4'.repeat(32)}`],
    [{ actor_kind: 'node' as const, actor_id: '3'.repeat(32) }, `Node ${'3'.repeat(32)}`],
    [{ actor_kind: 'unauthenticated' as const }, 'Unauthenticated'],
    [{ actor_kind: 'legacy_unknown' as const }, 'Legacy actor'],
  ])('renders controller actor provenance without inventing a browser label', (event, expected) => {
    expect(formatControllerAuditActor(event)).toBe(expected)
  })
})
