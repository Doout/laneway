import { render, screen } from '@testing-library/react'
import { expect, test } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { ControlPlaneProvider } from '../../lib/control-plane'
import { AccessRulesPage } from './AccessPages'

test('renders the access inventory and rule inspector', () => {
  render(<ControlPlaneProvider><MemoryRouter><AccessRulesPage /></MemoryRouter></ControlPlaneProvider>)
  expect(screen.getByRole('heading', { name: 'Access rules' })).toBeInTheDocument()
  expect(screen.getByText('Inspector')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Open rule' })).toHaveAttribute('href', '/access/acl_01J8EXPIRED')
})
