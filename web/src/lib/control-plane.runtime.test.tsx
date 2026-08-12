import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ControlPlaneProvider, useControlPlane } from './control-plane'

const principalId = '1'.repeat(32)
const oldSessionId = '2'.repeat(32)
const newSessionId = '4'.repeat(32)
const networkId = '3'.repeat(32)
const csrf = 'c'.repeat(43)

function sessionView(sessionId = oldSessionId, overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000)
  return {
    principal_id: principalId,
    username: 'session-operator',
    role: 'operator',
    permissions: ['route.manage'],
    all_networks: false,
    network_ids: [networkId],
    session_id: sessionId,
    idle_lifetime_seconds: 1800,
    idle_expires_at_unix_seconds: now + 1800,
    absolute_expires_at_unix_seconds: now + 3600,
    csrf_token: csrf,
    ...overrides,
  }
}

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
}

function managementResponse(body: unknown, activeSessionId = oldSessionId) {
  const now = Math.floor(Date.now() / 1000)
  return jsonResponse(body, 200, {
    'X-Laneway-Session-ID': activeSessionId,
    'X-Laneway-Session-Idle-Expires-At': String(now + 1800),
    'X-Laneway-Session-Absolute-Expires-At': String(now + 3600),
  })
}

class FakeBroadcastChannel {
  static instances: FakeBroadcastChannel[] = []
  readonly messages: unknown[] = []
  private listeners: Array<(event: MessageEvent<unknown>) => void> = []

  constructor(readonly name: string) { FakeBroadcastChannel.instances.push(this) }
  addEventListener(_type: 'message', listener: (event: MessageEvent<unknown>) => void) { this.listeners.push(listener) }
  removeEventListener(_type: 'message', listener: (event: MessageEvent<unknown>) => void) { this.listeners = this.listeners.filter((candidate) => candidate !== listener) }
  postMessage(value: unknown) { this.messages.push(value) }
  close() {}
  emit(value: unknown) { for (const listener of this.listeners) listener(new MessageEvent('message', { data: value })) }
}

function Harness() {
  const control = useControlPlane()
  const [result, setResult] = useState('')
  const [pendingIssue, setPendingIssue] = useState(() => control.captureSessionBinding())
  const [networkChanges, setNetworkChanges] = useState(0)
  const [pendingNetworkIssue, setPendingNetworkIssue] = useState<ReturnType<typeof control.captureSessionBinding>>(null)
  return <>
    <output aria-label="auth state">{control.authState}</output>
    <output aria-label="session ID">{control.session?.sessionId ?? 'none'}</output>
    <output aria-label="selected network ID">{control.selectedNetworkId ?? 'none'}</output>
    <output aria-label="network count">{control.inventory?.networks.length ?? 0}</output>
    <output aria-label="inventory error">{control.inventoryError}</output>
    <output aria-label="auth error">{control.authError}</output>
    <output aria-label="result">{result}</output>
    <button onClick={() => void control.signIn('session-operator', 'a sufficiently long password').then((accepted) => setResult(accepted ? 'signed-in' : 'rejected'))}>Sign in</button>
    <button onClick={() => void control.rotateSession().then((accepted) => setResult(accepted ? 'rotated' : 'rotation-failed'))}>Rotate</button>
    <button onClick={() => void control.signOut().then((accepted) => setResult(accepted ? 'signed-out' : 'sign-out-failed'))}>Sign out</button>
    <button onClick={() => {
      const networks = control.inventory?.networks ?? []
      const next = networks.find((network) => network.network_id !== control.selectedNetworkId)
      if (next) {
        control.selectNetwork(next.network_id)
        setNetworkChanges((value) => value + 1)
      }
    }}>Select other network</button>
    <button onClick={() => control.selectNetwork(networkId)}>Select known network</button>
    <output aria-label="network changes">{networkChanges}</output>
    <button onClick={() => { const binding = control.captureSessionBinding(); setResult(binding && control.storeIssuedEnrollmentToken(binding, { kind: 'command', token: 'one-time-secret', heading: 'Issued', command: 'use-token' }) ? 'issued' : 'issue-failed') }}>Issue one-time token</button>
    <button onClick={() => { setPendingIssue(control.captureSessionBinding()); setResult('issue-pending') }}>Begin token issue</button>
    <button onClick={() => { setPendingNetworkIssue(control.captureSessionBinding()); setResult('network-issue-pending') }}>Begin network token issue</button>
    <button onClick={() => setResult(pendingIssue && control.storeIssuedEnrollmentToken(pendingIssue, { kind: 'command', token: 'one-time-secret', heading: 'Issued', command: 'use-token' }) ? 'issued' : 'issue-failed')}>Complete token issue</button>
    <button onClick={() => setResult(pendingNetworkIssue && control.storeIssuedEnrollmentToken(pendingNetworkIssue, { kind: 'command', token: 'one-time-secret', heading: 'Issued', command: 'use-token' }) ? 'issued' : 'issue-failed')}>Complete network token issue</button>
    <button onClick={() => setResult(control.takeIssuedEnrollmentToken()?.value.token ?? 'token-unavailable')}>Read one-time token</button>
    <button onClick={() => void control.request<{ value: string }>('/v1/admin/test', { method: 'POST', body: { change: true } }).then((body) => setResult(body.value)).catch((error: Error) => setResult(error.message))}>Mutate</button>
  </>
}

describe('cookie session runtime races', () => {
  afterEach(() => {
    cleanup()
    FakeBroadcastChannel.instances = []
    vi.unstubAllEnvs()
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  function renderHarness() {
    vi.stubEnv('MODE', 'live')
    vi.stubGlobal('BroadcastChannel', FakeBroadcastChannel)
    return render(<ControlPlaneProvider><Harness /></ControlPlaneProvider>)
  }

  it('adds the memory-only CSRF token to an unsafe request without Authorization', async () => {
    const calls: Array<{ path: string; init?: RequestInit }> = []
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      calls.push({ path, init })
      return Promise.resolve(path.endsWith('/auth/session') ? jsonResponse(sessionView()) : managementResponse({ value: 'changed' }))
    }))
    renderHarness()
    expect(await screen.findByLabelText('auth state')).toHaveTextContent('authenticated')
    fireEvent.click(screen.getByRole('button', { name: 'Mutate' }))
    expect(await screen.findByLabelText('result')).toHaveTextContent('changed')
    const mutation = calls.find((call) => call.path.endsWith('/v1/admin/test'))
    const headers = new Headers(mutation?.init?.headers)
    expect(headers.get('X-Laneway-CSRF')).toBe(csrf)
    expect(headers.has('Authorization')).toBe(false)
    expect(mutation?.init?.credentials).toBe('same-origin')
    expect(mutation?.init?.redirect).toBe('error')
  })

  it('rejects a management body when session response metadata is missing and reconciles authoritatively', async () => {
    let sessionReads = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) {
        sessionReads += 1
        return Promise.resolve(jsonResponse(sessionView(sessionReads === 1 ? oldSessionId : newSessionId)))
      }
      if (path.endsWith('/v1/admin/test')) return Promise.resolve(jsonResponse({ value: 'other-principal-data' }))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)

    fireEvent.click(screen.getByRole('button', { name: 'Mutate' }))

    expect(await screen.findByLabelText('result')).toHaveTextContent('The administrator session changed while the request was in progress.')
    expect(screen.getByLabelText('result')).not.toHaveTextContent('other-principal-data')
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)
    expect(FakeBroadcastChannel.instances[0].messages).toContainEqual({ type: 'cookie-changed', sessionId: undefined })
  })

  it('rejects a mismatched management body and reconciles without BroadcastChannel delivery', async () => {
    let sessionReads = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) {
        sessionReads += 1
        return Promise.resolve(jsonResponse(sessionView(sessionReads === 1 ? oldSessionId : newSessionId)))
      }
      if (path.endsWith('/v1/admin/test')) return Promise.resolve(managementResponse({ value: 'other-principal-data' }, newSessionId))
      throw new Error(`Unexpected request ${path}`)
    }))
    vi.stubEnv('MODE', 'live')
    vi.stubGlobal('BroadcastChannel', undefined)
    render(<ControlPlaneProvider><Harness /></ControlPlaneProvider>)
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)

    fireEvent.click(screen.getByRole('button', { name: 'Mutate' }))

    expect(await screen.findByLabelText('result')).toHaveTextContent('The administrator session changed while the request was in progress.')
    expect(screen.getByLabelText('result')).not.toHaveTextContent('other-principal-data')
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)
  })

  it('rejects a successful response body that finishes after another tab changes the session', async () => {
    let resolveBody!: (value: { value: string }) => void
    const delayedBody = new Promise<{ value: string }>((resolve) => { resolveBody = resolve })
    let sessionRestores = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) {
        sessionRestores += 1
        return Promise.resolve(jsonResponse(sessionView(sessionRestores === 1 ? oldSessionId : newSessionId)))
      }
      return Promise.resolve({ ok: true, status: 200, headers: managementResponse({}).headers, json: () => delayedBody } as Response)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Mutate' }))
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2))
    FakeBroadcastChannel.instances[0].emit({ type: 'session-changed', sessionId: newSessionId })
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)
    resolveBody({ value: 'stale-success' })
    expect(await screen.findByLabelText('result')).toHaveTextContent('The administrator session changed while the response was being read.')
    expect(screen.getByLabelText('result')).not.toHaveTextContent('stale-success')
  })

  it('fails closed when a successful rotation response is malformed', async () => {
    const calls: Array<{ path: string; init?: RequestInit }> = []
    let sessionReads = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      calls.push({ path, init })
      if (path.endsWith('/auth/session')) {
        sessionReads += 1
        return Promise.resolve(jsonResponse(sessionView(sessionReads === 1 ? oldSessionId : newSessionId)))
      }
      if (path.endsWith('/auth/session/rotate')) return Promise.resolve(jsonResponse({ session_id: newSessionId }))
      if (path.endsWith('/auth/logout')) return Promise.resolve(new Response(null, { status: 204 }))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('auth state')).toHaveTextContent('authenticated')
    fireEvent.click(screen.getByRole('button', { name: 'Rotate' }))
    expect(await screen.findByLabelText('result')).toHaveTextContent('rotation-failed')
    expect(screen.getByLabelText('auth state')).toHaveTextContent('anonymous')
    expect(screen.getByLabelText('session ID')).toHaveTextContent('none')
    const rotation = calls.find((call) => call.path.endsWith('/auth/session/rotate'))
    expect(new Headers(rotation?.init?.headers).get('X-Laneway-CSRF')).toBe(csrf)
    const cleanup = calls.find((call) => call.path.endsWith('/auth/logout'))
    expect(new Headers(cleanup?.init?.headers).get('X-Laneway-CSRF')).toBe(csrf)
  })

  it('actively clears a server session created by a malformed successful sign-in response', async () => {
    const replacementCsrf = 'd'.repeat(43)
    const calls: Array<{ path: string; init?: RequestInit }> = []
    let sessionReads = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      calls.push({ path, init })
      if (path.endsWith('/auth/session')) {
        sessionReads += 1
        return Promise.resolve(jsonResponse(sessionView(sessionReads === 1 ? oldSessionId : newSessionId, sessionReads === 1 ? {} : { csrf_token: replacementCsrf })))
      }
      if (path.endsWith('/auth/login')) return Promise.resolve(jsonResponse({ session_id: newSessionId }))
      if (path.endsWith('/auth/logout')) return Promise.resolve(new Response(null, { status: 204 }))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByLabelText('result')).toHaveTextContent('rejected')
    expect(screen.getByLabelText('auth state')).toHaveTextContent('anonymous')
    expect(screen.getByLabelText('session ID')).toHaveTextContent('none')
    const cleanup = calls.find((call) => call.path.endsWith('/auth/logout'))
    expect(new Headers(cleanup?.init?.headers).get('X-Laneway-CSRF')).toBe(replacementCsrf)
  })

  it('broadcasts the old session identity when rotation reports it invalid', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(jsonResponse(sessionView()))
      if (path.endsWith('/auth/session/rotate')) return Promise.resolve(jsonResponse({ error: 'invalid session' }, 401))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Rotate' }))
    expect(await screen.findByLabelText('auth state')).toHaveTextContent('anonymous')
    expect(FakeBroadcastChannel.instances[0].messages).toContainEqual({ type: 'logout', sessionId: oldSessionId })
  })

  it('does not let a delayed bootstrap-state body replace a newer sign-in', async () => {
    let resolveState!: (value: { state: 'bootstrap_required' }) => void
    const delayedState = new Promise<{ state: 'bootstrap_required' }>((resolve) => { resolveState = resolve })
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(jsonResponse({ error: 'unauthorized' }, 401))
      if (path.endsWith('/auth/state')) return Promise.resolve({ ok: true, status: 200, json: () => delayedState } as Response)
      if (path.endsWith('/auth/login')) return Promise.resolve(jsonResponse(sessionView(newSessionId)))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2))
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)
    resolveState({ state: 'bootstrap_required' })
    await Promise.resolve()
    expect(screen.getByLabelText('auth state')).toHaveTextContent('authenticated')
    expect(screen.getByLabelText('result')).toHaveTextContent('signed-in')
  })

  it('reconciles a successful sign-in response that arrives after a newer sign-in', async () => {
    const authoritativeSessionId = '6'.repeat(32)
    let resolveLogin!: (value: Response) => void
    const delayedLogin = new Promise<Response>((resolve) => { resolveLogin = resolve })
    let loginCalls = 0
    let sessionReads = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) {
        sessionReads += 1
        return Promise.resolve(jsonResponse(sessionView(sessionReads === 1 ? oldSessionId : authoritativeSessionId)))
      }
      if (path.endsWith('/auth/login')) {
        loginCalls += 1
        return loginCalls === 1 ? delayedLogin : Promise.resolve(jsonResponse(sessionView(newSessionId)))
      }
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)

    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    await waitFor(() => expect(loginCalls).toBe(1))
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)
    resolveLogin(jsonResponse(sessionView('5'.repeat(32))))

    await waitFor(() => expect(screen.getByLabelText('session ID')).toHaveTextContent(authoritativeSessionId))
    expect(FakeBroadcastChannel.instances[0].messages).toContainEqual({ type: 'cookie-changed', sessionId: undefined })
    expect(sessionReads).toBe(2)
  })

  it('revalidates a family logout after this tab successfully rotated to a newer session ID', async () => {
    let sessionReads = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/state')) return Promise.resolve(jsonResponse({ state: 'sign_in' }))
      if (path.endsWith('/auth/session/rotate')) return Promise.resolve(jsonResponse(sessionView(newSessionId)))
      sessionReads += 1
      return Promise.resolve(sessionReads === 1
        ? jsonResponse(sessionView(oldSessionId))
        : jsonResponse({ error: 'revoked session family' }, 401))
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Rotate' }))
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)
    FakeBroadcastChannel.instances[0].emit({ type: 'logout', sessionId: oldSessionId })
    expect(await screen.findByLabelText('auth state')).toHaveTextContent('anonymous')
    expect(screen.getByLabelText('session ID')).toHaveTextContent('none')
    expect(sessionReads).toBe(2)
  })

  it('reconciles a logout message that arrives while a session read is pending', async () => {
    let resolveRead!: (value: Response) => void
    const delayedRead = new Promise<Response>((resolve) => { resolveRead = resolve })
    let reads = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/state')) return Promise.resolve(jsonResponse({ state: 'sign_in' }))
      reads += 1
      if (reads === 1) return Promise.resolve(jsonResponse(sessionView()))
      if (reads === 2) return delayedRead
      return Promise.resolve(jsonResponse({ error: 'revoked session family' }, 401))
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)

    FakeBroadcastChannel.instances[0].emit({ type: 'session-changed', sessionId: newSessionId })
    await waitFor(() => expect(reads).toBe(2))
    FakeBroadcastChannel.instances[0].emit({ type: 'logout', sessionId: oldSessionId })
    await waitFor(() => expect(reads).toBe(3))
    resolveRead(jsonResponse(sessionView(newSessionId)))

    expect(await screen.findByLabelText('auth state')).toHaveTextContent('anonymous')
    expect(screen.getByLabelText('session ID')).toHaveTextContent('none')
  })

  it('retains the authenticated session when logout cannot reach the controller', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(jsonResponse(sessionView()))
      if (path.endsWith('/auth/logout')) return Promise.reject(new TypeError('network unavailable'))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(await screen.findByLabelText('result')).toHaveTextContent('sign-out-failed')
    expect(screen.getByLabelText('auth state')).toHaveTextContent('authenticated')
    expect(screen.getByLabelText('session ID')).toHaveTextContent(oldSessionId)
    expect(screen.getByLabelText('auth error')).toHaveTextContent('Sign out could not be confirmed')
  })

  it('revalidates an idle deadline instead of expiring an active shared cookie locally', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    let restores = 0
    const now = Math.floor(Date.now() / 1000)
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (!path.endsWith('/auth/session')) throw new Error(`Unexpected request ${path}`)
      restores += 1
      return Promise.resolve(jsonResponse(sessionView(restores === 1 ? oldSessionId : newSessionId, restores === 1 ? { idle_expires_at_unix_seconds: now + 1 } : {})))
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    await act(async () => { await vi.advanceTimersByTimeAsync(1_100) })
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)
    expect(screen.getByLabelText('auth state')).toHaveTextContent('authenticated')
  })

  it('does not apply a stale request error after a newer session is installed', async () => {
    let resolveError!: (value: { error: string }) => void
    const delayedError = new Promise<{ error: string }>((resolve) => { resolveError = resolve })
    let restores = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) {
        restores += 1
        return Promise.resolve(jsonResponse(sessionView(restores === 1 ? oldSessionId : newSessionId)))
      }
      return Promise.resolve({ ok: false, status: 403, headers: new Headers(), json: () => delayedError } as Response)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Mutate' }))
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2))
    FakeBroadcastChannel.instances[0].emit({ type: 'session-changed', sessionId: newSessionId })
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)
    resolveError({ error: 'stale permission error' })
    expect(await screen.findByLabelText('result')).toHaveTextContent('The administrator session changed while the error response was being read.')
    expect(screen.getByLabelText('auth state')).toHaveTextContent('authenticated')
    expect(screen.getByLabelText('auth error')).toBeEmptyDOMElement()
  })

  it('authoritatively reconciles a stale rotation error after a newer sign-in', async () => {
    let resolveError!: (value: { error: string }) => void
    const delayedError = new Promise<{ error: string }>((resolve) => { resolveError = resolve })
    let sessionReads = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) {
        sessionReads += 1
        return Promise.resolve(jsonResponse(sessionView()))
      }
      if (path.endsWith('/auth/session/rotate')) return Promise.resolve({ ok: false, status: 500, headers: new Headers(), json: () => delayedError } as Response)
      if (path.endsWith('/auth/login')) return Promise.resolve(jsonResponse(sessionView(newSessionId)))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Rotate' }))
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2))
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)
    resolveError({ error: 'stale rotation failure' })
    await waitFor(() => expect(screen.getByLabelText('result')).toHaveTextContent('rotation-failed'))
    await waitFor(() => expect(screen.getByLabelText('session ID')).toHaveTextContent(oldSessionId))
    expect(screen.getByLabelText('auth state')).toHaveTextContent('authenticated')
    expect(screen.getByLabelText('auth error')).toBeEmptyDOMElement()
    expect(FakeBroadcastChannel.instances[0].messages).toContainEqual({ type: 'cookie-changed', sessionId: undefined })
    expect(sessionReads).toBe(2)
  })

  it('reconciles a successful rotation response that arrives after a newer sign-in', async () => {
    let resolveRotation!: (value: Response) => void
    const delayedRotation = new Promise<Response>((resolve) => { resolveRotation = resolve })
    let sessionReads = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) {
        sessionReads += 1
        return Promise.resolve(jsonResponse(sessionView(sessionReads === 1 ? oldSessionId : '6'.repeat(32))))
      }
      if (path.endsWith('/auth/session/rotate')) return delayedRotation
      if (path.endsWith('/auth/login')) return Promise.resolve(jsonResponse(sessionView(newSessionId)))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Rotate' }))
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2))
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)

    resolveRotation(jsonResponse(sessionView('6'.repeat(32))))

    expect(await screen.findByLabelText('session ID')).toHaveTextContent('6'.repeat(32))
    expect(FakeBroadcastChannel.instances[0].messages).toContainEqual({ type: 'cookie-changed', sessionId: undefined })
    expect(sessionReads).toBe(2)
  })

  it('authoritatively reconciles any stale logout response after a newer sign-in', async () => {
    let resolveError!: (value: { error: string }) => void
    const delayedError = new Promise<{ error: string }>((resolve) => { resolveError = resolve })
    let sessionReads = 0
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) {
        sessionReads += 1
        return Promise.resolve(jsonResponse(sessionView()))
      }
      if (path.endsWith('/auth/logout')) return Promise.resolve({ ok: false, status: 500, headers: new Headers(), json: () => delayedError } as Response)
      if (path.endsWith('/auth/login')) return Promise.resolve(jsonResponse(sessionView(newSessionId)))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2))
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)
    resolveError({ error: 'stale logout failure' })
    await waitFor(() => expect(screen.getByLabelText('result')).toHaveTextContent('sign-out-failed'))
    await waitFor(() => expect(screen.getByLabelText('session ID')).toHaveTextContent(oldSessionId))
    expect(screen.getByLabelText('auth state')).toHaveTextContent('authenticated')
    expect(screen.getByLabelText('auth error')).toBeEmptyDOMElement()
    expect(FakeBroadcastChannel.instances[0].messages).toContainEqual({ type: 'cookie-changed', sessionId: undefined })
    expect(sessionReads).toBe(2)
  })

  it('rejects a one-time token result that arrives after the session rotates', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(jsonResponse(sessionView()))
      if (path.endsWith('/auth/session/rotate')) return Promise.resolve(jsonResponse(sessionView(newSessionId)))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Begin token issue' }))
    expect(screen.getByLabelText('result')).toHaveTextContent('issue-pending')
    fireEvent.click(screen.getByRole('button', { name: 'Rotate' }))
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(newSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Complete token issue' }))
    expect(screen.getByLabelText('result')).toHaveTextContent('issue-failed')
    fireEvent.click(screen.getByRole('button', { name: 'Read one-time token' }))
    expect(screen.getByLabelText('result')).toHaveTextContent('token-unavailable')
  })

  it('rejects a one-time token result when the selected network changes', async () => {
    const otherNetworkId = '5'.repeat(32)
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(jsonResponse(sessionView(oldSessionId, {
        role: 'owner', permissions: ['network.list'], all_networks: true, network_ids: [],
      })))
      if (path.includes('/v1/admin/networks?limit=100')) return Promise.resolve(managementResponse({ networks: [
        { network_id: networkId, name: 'First network', ipv4_pool: '100.64.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 1 },
        { network_id: otherNetworkId, name: 'Second network', ipv4_pool: '100.65.0.0/24', configuration_epoch: 1, created_at_unix_seconds: 2 },
      ] }, oldSessionId))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.filter(([input]) => String(input).includes('/v1/admin/networks?limit=100'))).toHaveLength(1))
    await waitFor(() => expect(screen.getByLabelText('network count')).toHaveTextContent('2'))
    await waitFor(() => expect(screen.getByLabelText('selected network ID')).toHaveTextContent('none'))

    fireEvent.click(screen.getByRole('button', { name: 'Select known network' }))
    await waitFor(() => expect(screen.getByLabelText('selected network ID')).toHaveTextContent(networkId))
    fireEvent.click(screen.getByRole('button', { name: 'Begin network token issue' }))
    fireEvent.click(screen.getByRole('button', { name: 'Select other network' }))
    expect(screen.getByLabelText('network changes')).toHaveTextContent('1')
    expect(screen.getByLabelText('selected network ID')).toHaveTextContent(otherNetworkId)
    fireEvent.click(screen.getByRole('button', { name: 'Complete network token issue' }))

    expect(screen.getByLabelText('result')).toHaveTextContent('issue-failed')
    fireEvent.click(screen.getByRole('button', { name: 'Read one-time token' }))
    expect(screen.getByLabelText('result')).toHaveTextContent('token-unavailable')
  })

  it('rejects a one-time token result that arrives after logout', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (path.endsWith('/auth/session')) return Promise.resolve(jsonResponse(sessionView()))
      if (path.endsWith('/auth/logout')) return Promise.resolve(new Response(null, { status: 204 }))
      throw new Error(`Unexpected request ${path}`)
    }))
    renderHarness()
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    fireEvent.click(screen.getByRole('button', { name: 'Begin token issue' }))
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(await screen.findByLabelText('auth state')).toHaveTextContent('anonymous')
    fireEvent.click(screen.getByRole('button', { name: 'Complete token issue' }))
    expect(screen.getByLabelText('result')).toHaveTextContent('issue-failed')
    fireEvent.click(screen.getByRole('button', { name: 'Read one-time token' }))
    expect(screen.getByLabelText('result')).toHaveTextContent('token-unavailable')
  })

  it('revalidates on pageshow and visibility without BroadcastChannel support', async () => {
    vi.stubGlobal('BroadcastChannel', undefined)
    let reads = 0
    const visibleSessionId = '6'.repeat(32)
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const path = String(input)
      if (!path.endsWith('/auth/session')) throw new Error(`Unexpected request ${path}`)
      reads += 1
      return Promise.resolve(jsonResponse(sessionView(reads === 1 ? oldSessionId : reads === 2 ? newSessionId : visibleSessionId)))
    }))
    vi.stubEnv('MODE', 'live')
    render(<ControlPlaneProvider><Harness /></ControlPlaneProvider>)
    expect(await screen.findByLabelText('session ID')).toHaveTextContent(oldSessionId)
    await act(async () => { window.dispatchEvent(new PageTransitionEvent('pageshow')) })
    await waitFor(() => expect(screen.getByLabelText('session ID')).toHaveTextContent(newSessionId))
    document.dispatchEvent(new Event('visibilitychange'))
    await waitFor(() => expect(screen.getByLabelText('session ID')).toHaveTextContent(visibleSessionId))
    expect(reads).toBe(3)
  })
})
