import { render, screen } from '@testing-library/react'
import { expect, test } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { ControlPlaneProvider } from '../../lib/control-plane'
import { UsersListPage } from './index'

test('renders the user inventory with its selected inspector', () => {
  render(<ControlPlaneProvider><MemoryRouter><UsersListPage /></MemoryRouter></ControlPlaneProvider>)
  expect(screen.getByRole('heading', { name: 'Users' })).toBeInTheDocument()
  expect(screen.getByText('Inspector')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'View details' })).toHaveAttribute('href', '/users/usr_01J8PRIMARY4')
})
