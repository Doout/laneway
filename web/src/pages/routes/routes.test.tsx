import { render, screen, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { ControlPlaneProvider } from '../../lib/control-plane'
import { RoutesListPage } from './RoutesPages'

test('honors the pending route query and exposes the approval queue', () => {
  render(<ControlPlaneProvider><MemoryRouter initialEntries={['/routes?state=pending']}><RoutesListPage /></MemoryRouter></ControlPlaneProvider>)
  expect(screen.getAllByText('Kubernetes API')).toHaveLength(2)
  expect(screen.queryByText('Production services')).not.toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Review request' })).toHaveAttribute('href', '/routes/rte_01J8KUBEAPI/approve')
})

test('restores the approved route query', () => {
  const { container } = render(<ControlPlaneProvider><MemoryRouter initialEntries={['/routes?state=approved']}><RoutesListPage /></MemoryRouter></ControlPlaneProvider>)
  const view = within(container)
  expect(view.getByRole('button', { name: 'Healthy' })).toHaveClass('is-active')
  expect(view.getAllByText('Production services')).toHaveLength(2)
  expect(view.queryByText('Kubernetes API')).not.toBeInTheDocument()
})
