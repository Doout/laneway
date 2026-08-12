import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it } from 'vitest'
import { ControlPlaneProvider } from '../../lib/control-plane'
import { InfrastructurePage } from './InfrastructurePage'
import { NetworkDetailPage } from './NetworkDetailPage'

function renderRoute(path: string, element: React.ReactNode, pattern = path) {
  return render(<MemoryRouter initialEntries={[path]}><ControlPlaneProvider><Routes><Route path={pattern} element={element} /></Routes></ControlPlaneProvider></MemoryRouter>)
}

describe('infrastructure redesign flows', () => {
  beforeEach(() => window.localStorage.clear())

  it('creates a network from the topology-first inventory', async () => {
    const user = userEvent.setup()
    renderRoute('/infrastructure', <InfrastructurePage />)
    expect(screen.getByRole('heading', { name: 'Network topology' })).toBeVisible()
    await user.click(screen.getByRole('button', { name: /add network/i }))
    await user.type(screen.getByLabelText('Network name'), 'Disaster recovery')
    await user.click(screen.getByRole('button', { name: 'Create network' }))
    expect(await screen.findByRole('link', { name: /Disaster recovery/i })).toHaveAttribute('href', '/infrastructure/networks/disaster-recovery')
  })

  it('renders an explicit state for an unknown network identity', () => {
    renderRoute('/infrastructure/networks/missing', <NetworkDetailPage />, '/infrastructure/networks/:networkId')
    expect(screen.getByRole('heading', { name: 'Network not found' })).toBeVisible()
    expect(screen.getByText(/matches “missing”/)).toBeVisible()
  })
})
