import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { App } from './App'
import { ControlPlaneProvider } from './lib/control-plane'

function renderApp(path: string) {
  return render(<ControlPlaneProvider><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></ControlPlaneProvider>)
}

describe('Laneway application shell', () => {
  afterEach(() => {
    cleanup()
    vi.unstubAllEnvs()
    vi.unstubAllGlobals()
    window.sessionStorage.clear()
    window.localStorage.clear()
  })

  it('lands on the controller sign-in screen', async () => {
    renderApp('/')
    expect(await screen.findByRole('heading', { name: 'Sign in to Laneway' })).toBeVisible()
    expect(screen.getByRole('button', { name: 'SSO unavailable' })).toBeDisabled()
  })

  it('removes legacy client-only labels on initialization', async () => {
    vi.stubEnv('MODE', 'live')
    vi.stubEnv('VITE_LANEWAY_API_ORIGIN', 'https://controller.example:8443/')
    window.sessionStorage.setItem('laneway-console-operator', 'Legacy label')
    renderApp('/sign-in')
    expect(screen.getByLabelText('Controller address')).toHaveValue('https://controller.example:8443')
    expect(screen.queryByLabelText('Session label')).not.toBeInTheDocument()
    expect(screen.queryByText('Displayed only in this browser session.')).not.toBeInTheDocument()
    expect(screen.getByText('Stored for this browser session and sent with controller requests.')).toBeVisible()
    expect(screen.queryByText('Legacy label')).not.toBeInTheDocument()
    await waitFor(() => expect(window.sessionStorage.getItem('laneway-console-operator')).toBeNull())
  })

  it('keeps a forbidden saved session without rendering empty inventory as controller state', async () => {
    vi.stubEnv('MODE', 'live')
    window.sessionStorage.setItem('laneway-console-admin-token', 'restricted-token')
    window.sessionStorage.setItem('laneway-console-operator', 'Restricted session')
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ networks: [] }) })
      .mockResolvedValueOnce({ ok: false, status: 403, json: async () => ({ error: 'forbidden' }) }))

    renderApp('/overview')
    expect(await screen.findByRole('alert')).toHaveTextContent('forbidden')
    expect(screen.queryByRole('heading', { level: 1, name: 'Overview' })).not.toBeInTheDocument()
    expect(window.sessionStorage.getItem('laneway-console-admin-token')).toBe('restricted-token')
    expect(window.sessionStorage.getItem('laneway-console-operator')).toBeNull()
  })

  it('fails closed when the controller has multiple networks', async () => {
    vi.stubEnv('MODE', 'live')
    window.sessionStorage.setItem('laneway-console-admin-token', 'valid-token')
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ networks: [{ network_id: 'one' }] }) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ networks: [{ network_id: 'one' }, { network_id: 'two' }] }) }))

    renderApp('/overview')

    expect(await screen.findByRole('alert')).toHaveTextContent('This console supports one network')
    expect(screen.queryByRole('heading', { level: 1, name: 'Overview' })).not.toBeInTheDocument()
    expect(window.sessionStorage.getItem('laneway-console-admin-token')).toBe('valid-token')
  })

  it('clears a rejected saved session and its legacy label', async () => {
    vi.stubEnv('MODE', 'live')
    window.sessionStorage.setItem('laneway-console-admin-token', 'expired-token')
    window.sessionStorage.setItem('laneway-console-operator', 'Private operator')
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: 'unauthorized' }),
    }))

    renderApp('/overview')
    expect(screen.queryByText('Private operator')).not.toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: 'Sign in to Laneway' })).toBeVisible()
    expect(window.sessionStorage.getItem('laneway-console-admin-token')).toBeNull()
    expect(window.sessionStorage.getItem('laneway-console-operator')).toBeNull()
  })

  it('restores an accepted controller session without restoring its legacy label', async () => {
    vi.stubEnv('MODE', 'live')
    window.sessionStorage.setItem('laneway-console-admin-token', 'valid-token')
    window.sessionStorage.setItem('laneway-console-operator', 'Private operator')
    let acceptSession!: (response: unknown) => void
    const restoreResponse = new Promise(resolve => { acceptSession = resolve })
    vi.stubGlobal('fetch', vi.fn()
      .mockReturnValueOnce(restoreResponse)
      .mockResolvedValue({ ok: true, status: 200, json: async () => ({ networks: [] }) }))

    renderApp('/overview')
    expect(screen.getByRole('status')).toHaveTextContent('Restoring controller session')
    expect(screen.queryByText('Private operator')).not.toBeInTheDocument()
    acceptSession({ ok: true, status: 200, json: async () => ({ networks: [] }) })
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeVisible()
    expect(screen.queryByText('Private operator')).not.toBeInTheDocument()
    expect(window.sessionStorage.getItem('laneway-console-operator')).toBeNull()
  })

  it('does not let a stale restore invalidate a newer sign-in', async () => {
    vi.stubEnv('MODE', 'live')
    window.sessionStorage.setItem('laneway-console-admin-token', 'expired-token')
    window.sessionStorage.setItem('laneway-console-operator', 'Previous label')
    let rejectRestore!: (response: unknown) => void
    const restoreResponse = new Promise(resolve => { rejectRestore = resolve })
    vi.stubGlobal('fetch', vi.fn()
      .mockReturnValueOnce(restoreResponse)
      .mockResolvedValue({ ok: true, status: 200, json: async () => ({ networks: [] }) }))

    renderApp('/sign-in')
    fireEvent.change(screen.getByLabelText('Administrator token'), { target: { value: 'current-token' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeVisible()

    await act(async () => {
      rejectRestore({ ok: false, status: 401, json: async () => ({ error: 'unauthorized' }) })
      await restoreResponse
    })
    expect(window.sessionStorage.getItem('laneway-console-admin-token')).toBe('current-token')
    expect(screen.getByRole('heading', { name: 'Overview' })).toBeVisible()
    expect(window.sessionStorage.getItem('laneway-console-operator')).toBeNull()
  })

  it('ignores inventory that finishes after signing into a newer session', async () => {
    vi.stubEnv('MODE', 'live')
    let resolveOldInventory!: (response: unknown) => void
    let resolveNewInventory!: (response: unknown) => void
    const oldInventory = new Promise(resolve => { resolveOldInventory = resolve })
    const newInventory = new Promise(resolve => { resolveNewInventory = resolve })
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ networks: [] }) })
      .mockReturnValueOnce(oldInventory)
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ networks: [] }) })
      .mockReturnValueOnce(newInventory)
    vi.stubGlobal('fetch', fetchMock)

    renderApp('/sign-in')
    fireEvent.change(screen.getByLabelText('Administrator token'), { target: { value: 'old-session-token' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Loading inventory')
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))

    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('heading', { name: 'Sign in to Laneway' })).toBeVisible()
    fireEvent.change(screen.getByLabelText('Administrator token'), { target: { value: 'new-session-token' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Loading inventory')
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(4))

    await act(async () => {
      resolveOldInventory({ ok: true, status: 200, json: async () => ({ networks: [] }) })
      await oldInventory
    })
    expect(screen.queryByRole('heading', { level: 1, name: 'Overview' })).not.toBeInTheDocument()

    await act(async () => {
      resolveNewInventory({ ok: true, status: 200, json: async () => ({ networks: [] }) })
      await newInventory
    })
    expect(await screen.findByRole('heading', { level: 1, name: 'Overview' })).toBeVisible()
    expect(window.sessionStorage.getItem('laneway-console-admin-token')).toBe('new-session-token')
  })

  it('labels authenticated records as demo data', () => {
    renderApp('/overview')
    expect(screen.getByRole('note', { name: 'Demo data notice' })).toHaveTextContent('Demo data')
  })
})
