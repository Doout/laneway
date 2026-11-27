import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { TwingatePage } from './TwingatePage'

const request = vi.hoisted(() => vi.fn())
vi.mock('../../lib/control-plane', () => ({ useControlPlane: () => ({ request }) }))

const saved = { tenant: 'team', verified_at_unix_seconds: 1_700_000_000 }
const resource = {
  id: 'one', name: 'Registry', kind: 'NetworkResource', active: true, alias: 'registry.internal',
  address: { value: '10.0.0.1' }, remote_network: { name: 'Lab' },
  protocols: { tcp: { policy: 'ALLOW_ALL', ports: [] }, udp: { policy: 'RESTRICTED', ports: [] }, allow_icmp: true },
}
const result = { resources: [resource], total_count: 2, next_cursor: 'cursor' }

afterEach(() => { cleanup(); request.mockReset() })

it('opens saved settings on demand and keeps the saved network after a failed replacement', async () => {
  request.mockResolvedValueOnce(saved).mockResolvedValueOnce(result).mockRejectedValueOnce(new Error('Token rejected'))
  render(<MemoryRouter><TwingatePage /></MemoryRouter>)
  const settings = await screen.findByRole('button', { name: 'Connection settings' })
  expect(settings).toHaveAttribute('aria-expanded', 'false')
  expect(screen.getByLabelText('New API token')).not.toBeVisible()
  fireEvent.click(settings)
  expect(settings).toHaveAttribute('aria-expanded', 'true')
  fireEvent.change(screen.getByLabelText('Twingate network'), { target: { value: 'alternate' } })
  fireEvent.change(screen.getByLabelText('New API token'), { target: { value: 'test-token' } })
  fireEvent.click(screen.getByRole('button', { name: 'Test and save' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Token rejected')
  expect(screen.getByRole('heading', { name: 'team.twingate.com' })).toBeVisible()
  expect(screen.getByRole('checkbox', { name: 'Select Registry' })).toBeVisible()
})

it('keeps the last loaded page visible during a pagination failure and retries the failed cursor', async () => {
  request.mockResolvedValueOnce(saved).mockResolvedValueOnce(result).mockRejectedValueOnce(new Error('Unavailable'))
    .mockResolvedValueOnce({ ...result, resources: [{ ...resource, id: 'two', name: 'Analytics' }], next_cursor: null })
  render(<MemoryRouter><TwingatePage /></MemoryRouter>)
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select Registry' }))
  fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Showing the last loaded results from page 1.')
  expect(screen.getByRole('checkbox', { name: 'Select Registry' })).toBeChecked()
  fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
  expect(await screen.findByText('Analytics')).toBeVisible()
  expect(request.mock.calls.at(-1)?.[0]).toMatch(/resources\?after=cursor$/)
  expect(screen.getByText('Page 2')).toBeVisible()
  expect(screen.getByText('1 selected')).toBeVisible()
})
