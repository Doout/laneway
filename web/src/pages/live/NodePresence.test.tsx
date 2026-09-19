import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import { NodePresence } from './NodePresence'

afterEach(cleanup)
const record = { node_id: 'a'.repeat(32), source: 'unknown' as const, observed_at_unix_seconds: 0, stale: false, online: true, last_seen_unix_seconds: Math.floor(Date.now() / 1000), public_ip: '8.8.8.8' }
it('shows a fresh heartbeat and observed IP', () => {
  render(<NodePresence record={record} unavailable={false} />)
  expect(screen.getByText('Online')).toBeVisible()
  expect(screen.getByText('8.8.8.8')).toBeVisible()
})
it('expires stale status even if the last response said online', () => {
  render(<NodePresence record={{ ...record, last_seen_unix_seconds: record.last_seen_unix_seconds - 361 }} unavailable={false} />)
  expect(screen.getByText('Offline')).toBeVisible()
})
it('does not confuse missing reports or failed requests with online', () => {
  const view = render(<NodePresence unavailable={false} />)
  expect(screen.getByText('No heartbeat')).toBeVisible()
  view.rerender(<NodePresence record={record} unavailable />)
  expect(screen.getByText('Status unavailable')).toBeVisible()
  expect(screen.queryByText('Online')).not.toBeInTheDocument()
})
