import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { ControlPlaneProvider } from '../../lib/control-plane'
import { AuditPage } from './AuditPage'

describe('audit split inspector', () => {
  it('moves event identity into the inspector and supports empty search recovery', async () => {
    const user = userEvent.setup()
    render(<MemoryRouter><ControlPlaneProvider><AuditPage /></ControlPlaneProvider></MemoryRouter>)
    await user.click(screen.getByRole('button', { name: /Relay probe failed/i }))
    expect(screen.getByRole('heading', { name: 'Relay probe failed' })).toBeVisible()
    await user.type(screen.getByRole('searchbox', { name: 'Search audit events' }), 'no-such-audit-event')
    expect(screen.getByRole('heading', { name: 'No matching events' })).toBeVisible()
  })
})
