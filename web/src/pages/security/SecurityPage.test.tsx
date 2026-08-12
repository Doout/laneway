import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it } from 'vitest'
import { ControlPlaneProvider } from '../../lib/control-plane'
import { SecurityPage } from './SecurityPage'

describe('security inventory redesign', () => {
  beforeEach(() => window.localStorage.clear())

  it('requires typed review before issuing a bearer credential', async () => {
    const user = userEvent.setup()
    render(<MemoryRouter><ControlPlaneProvider><SecurityPage /></ControlPlaneProvider></MemoryRouter>)
    await user.click(screen.getByRole('button', { name: /issue credential/i }))
    const confirmation = screen.getByLabelText('Type ISSUE TOKEN to confirm')
    expect(screen.getByRole('button', { name: 'Issue token' })).toBeDisabled()
    await user.type(confirmation, 'ISSUE TOKEN')
    await user.click(screen.getByRole('button', { name: 'Issue token' }))
    expect(await screen.findByRole('heading', { name: 'Enrollment token issued' })).toBeVisible()
  })
})
