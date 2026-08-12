import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type PropsWithChildren } from 'react'
import { purgeLegacyAuthStorage } from './legacy-auth-storage'

export const administratorPermissions = [
  'network.list',
  'network.read',
  'network.create',
  'enrollment.issue',
  'bootstrap_bundle.create',
  'node.read',
  'node.manage',
  'route.read',
  'route.manage',
  'acl.read',
  'acl.manage',
  'relay.read',
  'relay.manage',
  'certificate.read',
  'certificate.revoke',
  'audit.read',
  'audit.read_global',
  'principal.manage',
  'session.manage_others',
  'recovery.manage',
  'root_token.rotate',
] as const

export type AdministratorPermission = typeof administratorPermissions[number]
export type AdministratorRole = 'owner' | 'operator' | 'auditor'
export type AuthenticationState = 'checking' | 'bootstrap_required' | 'anonymous' | 'authenticated' | 'unavailable'

export type AdministratorSession = {
  principalId: string
  username: string
  role: AdministratorRole
  permissions: AdministratorPermission[]
  allNetworks: boolean
  networkIds: string[]
  sessionId: string
  idleLifetimeSeconds: number
  idleExpiresAtUnixSeconds: number
  absoluteExpiresAtUnixSeconds: number
}

export type IssuedEnrollmentToken =
  | { kind: 'command'; token: string; heading: string; command: string }
  | { kind: 'node'; token: string; name: string; nodeClass: string; expiry: string }
  | { kind: 'user'; token: string; tokenId: string; subject: string; enrollment: string; networkName: string; leaseHours: number }

export type AdministratorSessionBinding = {
  sessionId: string
  generation: number
  networkId: string | null
  networkGeneration: number
}

type SessionEnvelope = {
  session: AdministratorSession
  csrfToken: string
}

export type ControllerNetwork = {
  network_id: string
  name: string
  ipv4_pool: string
  ipv6_pool?: string
  configuration_epoch: number
  created_at_unix_seconds: number
}

export type ControllerNode = {
  node_id: string
  network_id: string
  name: string
  enabled_capabilities: number
  ipv4_address?: string
  ipv6_address?: string
  created_at_unix_seconds: number
  revoked_at_unix_seconds?: number
  enrollment_class: 'durable' | 'ephemeral' | 'remembered'
  lease_expires_at_unix_seconds?: number
}

export type ControllerRoute = {
  route_id: string
  network_id: string
  node_id: string
  prefix: string
  kind: 'overlay' | 'subnet' | 'exit'
  mode: 'none' | 'nat' | 'routed'
  metric: number
  state: 'advertised' | 'approved' | 'withdrawn' | 'rejected'
  valid_until_unix_seconds?: number
  created_at_unix_seconds: number
  approved_at_unix_seconds?: number
  withdrawn_at_unix_seconds?: number
}

export type ControllerACLRule = {
  rule_id: string
  network_id: string
  priority: number
  action: 'accept' | 'deny'
  selector: Record<string, unknown>
  description: string
  enabled: boolean
  configuration_epoch: number
}

export type ControllerRelay = {
  relay_id: string
  network_id: string
  service_id: string
  node_id?: string
  name: string
  endpoint: string
  enabled: boolean
  created_at_unix_seconds: number
  configuration_epoch: number
}

export type ControllerCertificate = {
  certificate_id: string
  network_id: string
  node_id: string
  serial: string
  not_before_unix_seconds: number
  not_after_unix_seconds: number
  created_at_unix_seconds: number
  revoked_at_unix_seconds?: number
  revocation_reason?: string
}

export type ControllerAuditEvent = {
  event_id: string
  network_id?: string
  actor_kind: 'system' | 'node' | 'administrator' | 'service_principal' | 'recovery_grant' | 'unauthenticated' | 'legacy_unknown'
  actor_id?: string
  actor_node_id?: string
  action: string
  target_type: string
  target_id?: string
  details: Record<string, unknown>
  created_at_unix_seconds: number
}

export type ControllerInventory = {
  networks: ControllerNetwork[]
  network: ControllerNetwork | null
  nodes: ControllerNode[]
  routes: ControllerRoute[]
  aclRules: ControllerACLRule[]
  relays: ControllerRelay[]
  certificates: ControllerCertificate[]
  auditEvents: ControllerAuditEvent[]
}

type RequestOptions = {
  method?: string
  body?: unknown
  signal?: AbortSignal
}

type ControlPlaneContextValue = {
  live: boolean
  authState: AuthenticationState
  authenticated: boolean
  sessionPending: boolean
  authPending: boolean
  authError: string
  session: AdministratorSession | null
  inventory: ControllerInventory | null
  inventoryPending: boolean
  inventoryError: string
  selectedNetworkId: string | null
  selectNetwork: (networkId: string) => void
  captureSessionBinding: () => AdministratorSessionBinding | null
  storeIssuedEnrollmentToken: (binding: AdministratorSessionBinding, value: IssuedEnrollmentToken) => boolean
  peekIssuedEnrollmentToken: () => { binding: AdministratorSessionBinding; value: IssuedEnrollmentToken } | null
  clearIssuedEnrollmentToken: (binding: AdministratorSessionBinding) => void
  takeIssuedEnrollmentToken: () => { binding: AdministratorSessionBinding; value: IssuedEnrollmentToken } | null
  isSessionBindingCurrent: (binding: AdministratorSessionBinding) => boolean
  signIn: (username: string, password: string) => Promise<boolean>
  signOut: () => Promise<boolean>
  retryAuthentication: () => Promise<void>
  rotateSession: () => Promise<boolean>
  hasPermission: (permission: AdministratorPermission, networkId?: string) => boolean
  refresh: () => Promise<void>
  request: <T>(path: string, options?: RequestOptions) => Promise<T>
}

const emptyInventory: ControllerInventory = {
  networks: [], network: null, nodes: [], routes: [], aclRules: [], relays: [], certificates: [], auditEvents: [],
}

const permissionNames = new Set<string>(administratorPermissions)
const networkScopedPermissionNames = new Set<AdministratorPermission>([
  'network.read', 'enrollment.issue', 'node.read', 'node.manage', 'route.read', 'route.manage',
  'acl.read', 'acl.manage', 'relay.read', 'relay.manage', 'certificate.read', 'certificate.revoke', 'audit.read',
])
const identityPattern = /^[0-9a-f]{32}$/
const csrfPattern = /^[A-Za-z0-9_-]{43}$/
const usernamePattern = /^[a-z0-9](?:[a-z0-9._-]{1,62}[a-z0-9])?$/
const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS'])

const ControlPlaneContext = createContext<ControlPlaneContextValue | null>(null)

export class ControllerRequestError extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
    this.name = 'ControllerRequestError'
  }
}

export function controllerOrigin() {
  return window.location.origin
}

export function parseConsoleBuildMode(value: unknown): 'live' | 'demo' {
  if (value === 'live' || value === 'demo') return value
  throw new Error(`Unsupported console build mode: ${String(value)}`)
}

export function isNetworkScopedAdministratorPermission(permission: AdministratorPermission) {
  return networkScopedPermissionNames.has(permission)
}

function isLiveMode() {
  return parseConsoleBuildMode(import.meta.env.MODE) === 'live'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseUnixSeconds(value: unknown, field: string) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`Invalid administrator session ${field}`)
  }
  return value
}

export function parseAdministratorSession(value: unknown): SessionEnvelope {
  if (!isRecord(value)) throw new Error('Invalid administrator session response')
  const principalId = value.principal_id
  const username = value.username
  const role = value.role
  const rawPermissions = value.permissions
  const allNetworks = value.all_networks
  const rawNetworkIds = value.network_ids
  const sessionId = value.session_id
  const csrfToken = value.csrf_token
  if (typeof principalId !== 'string' || !identityPattern.test(principalId) ||
    typeof username !== 'string' || !usernamePattern.test(username) || username.length < 3 || username.length > 64 ||
    (role !== 'owner' && role !== 'operator' && role !== 'auditor') ||
    !Array.isArray(rawPermissions) || !rawPermissions.every(permission => typeof permission === 'string' && permissionNames.has(permission)) ||
    typeof allNetworks !== 'boolean' || !Array.isArray(rawNetworkIds) ||
    !rawNetworkIds.every(networkId => typeof networkId === 'string' && identityPattern.test(networkId)) ||
    typeof sessionId !== 'string' || !identityPattern.test(sessionId) ||
    typeof csrfToken !== 'string' || !csrfPattern.test(csrfToken)) {
    throw new Error('Invalid administrator session response')
  }
  if (new Set(rawPermissions).size !== rawPermissions.length || new Set(rawNetworkIds).size !== rawNetworkIds.length) {
    throw new Error('Invalid administrator session response')
  }
  const permissions = rawPermissions as AdministratorPermission[]
  const networkIds = rawNetworkIds as string[]
  if (role === 'owner' && !allNetworks || allNetworks && networkIds.length !== 0) {
    throw new Error('Invalid administrator session scope')
  }
  const idleLifetimeSeconds = parseUnixSeconds(value.idle_lifetime_seconds, 'idle lifetime')
  const idleExpiresAtUnixSeconds = parseUnixSeconds(value.idle_expires_at_unix_seconds, 'idle deadline')
  const absoluteExpiresAtUnixSeconds = parseUnixSeconds(value.absolute_expires_at_unix_seconds, 'absolute deadline')
  if (idleLifetimeSeconds < 60 || idleLifetimeSeconds > 86_400 || idleExpiresAtUnixSeconds > absoluteExpiresAtUnixSeconds) {
    throw new Error('Invalid administrator session deadlines')
  }
  return {
    session: {
      principalId,
      username,
      role,
      permissions,
      allNetworks,
      networkIds,
      sessionId,
      idleLifetimeSeconds,
      idleExpiresAtUnixSeconds,
      absoluteExpiresAtUnixSeconds,
    },
    csrfToken,
  }
}

async function responseError(response: Response) {
  try {
    const body = await response.json() as { error?: string; message?: string; detail?: string }
    return body.error || body.message || body.detail || `Controller returned ${response.status}`
  } catch {
    return `Controller returned ${response.status}`
  }
}

function sameOriginPath(path: string) {
  if (!path.startsWith('/') || path.startsWith('//')) throw new Error('Controller request path must be same-origin')
  const target = new URL(path, window.location.origin)
  if (target.origin !== window.location.origin || !target.pathname.startsWith('/v1/')) {
    throw new Error('Controller request path must be same-origin')
  }
  return `${target.pathname}${target.search}`
}

function authFetch(path: string, init: RequestInit = {}) {
  return fetch(sameOriginPath(path), {
    ...init,
    credentials: 'same-origin',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
    redirect: 'error',
  })
}

export function ControlPlaneProvider({ children }: PropsWithChildren) {
  const live = isLiveMode()
  const [authState, setAuthState] = useState<AuthenticationState>(() => {
    purgeLegacyAuthStorage()
    return live ? 'checking' : 'authenticated'
  })
  const [authPending, setAuthPending] = useState(false)
  const [authError, setAuthError] = useState('')
  const [session, setSession] = useState<AdministratorSession | null>(null)
  const [inventory, setInventory] = useState<ControllerInventory | null>(live ? null : emptyInventory)
  const [inventoryPending, setInventoryPending] = useState(false)
  const [inventoryError, setInventoryError] = useState('')
  const [selectedNetworkId, setSelectedNetworkId] = useState<string | null>(null)
  const authGenerationRef = useRef(0)
  const sessionRef = useRef<AdministratorSession | null>(null)
  const csrfRef = useRef('')
  const restoreAbortRef = useRef<AbortController | null>(null)
  const sessionChannelRef = useRef<BroadcastChannel | null>(null)
  const inventoryRequestRef = useRef(0)
  const selectedNetworkIdRef = useRef<string | null>(null)
  const networkGenerationRef = useRef(0)
  const issuedEnrollmentTokenRef = useRef<{ binding: AdministratorSessionBinding; value: IssuedEnrollmentToken } | null>(null)

  const clearSessionSecrets = useCallback(() => {
    issuedEnrollmentTokenRef.current = null
  }, [])

  const resetInventory = useCallback(() => {
    inventoryRequestRef.current += 1
    networkGenerationRef.current += 1
    selectedNetworkIdRef.current = null
    setSelectedNetworkId(null)
    setInventory(live ? null : emptyInventory)
    setInventoryPending(false)
    setInventoryError('')
  }, [live])

  const notifyOtherTabs = useCallback((type: 'session-changed' | 'logout' | 'cookie-changed', sessionId?: string) => {
    sessionChannelRef.current?.postMessage({ type, sessionId })
  }, [])

  const installSession = useCallback((envelope: SessionEnvelope, generation: number) => {
    if (authGenerationRef.current !== generation) return false
    clearSessionSecrets()
    const expiresAt = Math.min(envelope.session.idleExpiresAtUnixSeconds, envelope.session.absoluteExpiresAtUnixSeconds) * 1000
    if (expiresAt <= Date.now()) {
      sessionRef.current = null
      csrfRef.current = ''
      setSession(null)
      setAuthState('anonymous')
      setAuthError('Your session expired. Sign in again.')
      resetInventory()
      return false
    }
    sessionRef.current = envelope.session
    csrfRef.current = envelope.csrfToken
    setSession(envelope.session)
    setAuthState('authenticated')
    setAuthError('')
    resetInventory()
    return true
  }, [clearSessionSecrets, resetInventory])

  const invalidateSession = useCallback((generation: number, message: string) => {
    if (authGenerationRef.current !== generation) return false
    clearSessionSecrets()
    authGenerationRef.current += 1
    sessionRef.current = null
    csrfRef.current = ''
    setSession(null)
    setAuthState('anonymous')
    setAuthError(message)
    setAuthPending(false)
    resetInventory()
    return true
  }, [clearSessionSecrets, resetInventory])

  const refreshSessionMetadata = useCallback((response: Response, generation: number) => {
    if (authGenerationRef.current !== generation) return false
    const sessionId = response.headers.get('X-Laneway-Session-ID')
    const idleValue = response.headers.get('X-Laneway-Session-Idle-Expires-At')
    const absoluteValue = response.headers.get('X-Laneway-Session-Absolute-Expires-At')
    if (sessionId === null || idleValue === null || absoluteValue === null) return false
    if (!identityPattern.test(sessionId) || !/^\d+$/.test(idleValue) || !/^\d+$/.test(absoluteValue)) return false
    const idleExpiresAtUnixSeconds = Number(idleValue)
    const absoluteExpiresAtUnixSeconds = Number(absoluteValue)
    const current = sessionRef.current
    if (!current || current.sessionId !== sessionId ||
      !Number.isSafeInteger(idleExpiresAtUnixSeconds) || !Number.isSafeInteger(absoluteExpiresAtUnixSeconds) ||
      idleExpiresAtUnixSeconds <= 0 || absoluteExpiresAtUnixSeconds <= 0 ||
      idleExpiresAtUnixSeconds > absoluteExpiresAtUnixSeconds) return false
    if (Math.min(idleExpiresAtUnixSeconds, absoluteExpiresAtUnixSeconds) * 1000 <= Date.now()) {
      invalidateSession(generation, 'Your session expired. Sign in again.')
      return false
    }
    if (current.idleExpiresAtUnixSeconds === idleExpiresAtUnixSeconds &&
      current.absoluteExpiresAtUnixSeconds === absoluteExpiresAtUnixSeconds) return true
    const refreshed = { ...current, idleExpiresAtUnixSeconds, absoluteExpiresAtUnixSeconds }
    sessionRef.current = refreshed
    setSession(refreshed)
    return true
  }, [invalidateSession])

  const retryAuthentication = useCallback(async () => {
    if (!live) return
    purgeLegacyAuthStorage()
    restoreAbortRef.current?.abort()
    const controller = new AbortController()
    restoreAbortRef.current = controller
    const generation = ++authGenerationRef.current
    clearSessionSecrets()
    sessionRef.current = null
    csrfRef.current = ''
    setSession(null)
    setAuthState('checking')
    setAuthPending(false)
    setAuthError('')
    resetInventory()
    try {
      const sessionResponse = await authFetch('/v1/admin/auth/session', {
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      })
      if (authGenerationRef.current !== generation || controller.signal.aborted) return
      if (sessionResponse.ok) {
        const envelope = parseAdministratorSession(await sessionResponse.json())
        if (authGenerationRef.current !== generation || controller.signal.aborted) return
        installSession(envelope, generation)
        return
      }
      if (sessionResponse.status !== 401) throw new Error(await responseError(sessionResponse))

      const stateResponse = await authFetch('/v1/admin/auth/state', {
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      })
      if (authGenerationRef.current !== generation || controller.signal.aborted) return
      if (!stateResponse.ok) throw new Error(await responseError(stateResponse))
      const stateBody = await stateResponse.json() as unknown
      if (authGenerationRef.current !== generation || controller.signal.aborted) return
      if (!isRecord(stateBody) || (stateBody.state !== 'bootstrap_required' && stateBody.state !== 'sign_in')) {
        throw new Error('Invalid administrator authentication state')
      }
      setAuthState(stateBody.state === 'bootstrap_required' ? 'bootstrap_required' : 'anonymous')
    } catch (error) {
      if (controller.signal.aborted || authGenerationRef.current !== generation) return
      setAuthState('unavailable')
      setAuthError(error instanceof Error ? error.message : 'Controller authentication is unavailable.')
    }
  }, [clearSessionSecrets, installSession, live, resetInventory])

  const reconcileCredentialCookieMutation = useCallback(async () => {
    // Set-Cookie is applied before fetch resolves, so a response that lost a
    // local generation race can still have changed credentials for every tab.
    // This event never originates from retryAuthentication, which keeps the
    // authoritative reconciliation from forming a broadcast loop.
    notifyOtherTabs('cookie-changed')
    await retryAuthentication()
  }, [notifyOtherTabs, retryAuthentication])

  useEffect(() => {
    if (!live || typeof window.BroadcastChannel !== 'function') return
    const channel = new BroadcastChannel('laneway-administrator-session')
    sessionChannelRef.current = channel
    channel.addEventListener('message', (event: MessageEvent<unknown>) => {
      if (!isRecord(event.data)) return
      if (event.data.type === 'cookie-changed') {
        void retryAuthentication()
      } else if (event.data.type === 'logout') {
        const current = sessionRef.current
        if (typeof event.data.sessionId === 'string' && current?.sessionId === event.data.sessionId) {
          invalidateSession(authGenerationRef.current, 'Your session ended in another browser tab.')
        } else {
          // Rotation gives tabs different IDs within one revocation family.
          // A logout for an older ID may still have revoked the current one.
          void retryAuthentication()
        }
      } else if (event.data.type === 'session-changed') {
        const current = sessionRef.current
        if (typeof event.data.sessionId === 'string' && current?.sessionId !== event.data.sessionId) void retryAuthentication()
      }
    })
    return () => {
      if (sessionChannelRef.current === channel) sessionChannelRef.current = null
      channel.close()
    }
  }, [invalidateSession, live, retryAuthentication])

  useEffect(() => {
    if (!live) return
    void retryAuthentication()
    return () => restoreAbortRef.current?.abort()
  }, [live, retryAuthentication])

  useEffect(() => {
    if (!live || authState !== 'authenticated' || !session) return
    const generation = authGenerationRef.current
    const expiresAt = Math.min(session.idleExpiresAtUnixSeconds, session.absoluteExpiresAtUnixSeconds) * 1000
    const expire = () => {
      if (Date.now() >= expiresAt && authGenerationRef.current === generation) void retryAuthentication()
    }
    const delay = Math.max(0, Math.min(expiresAt - Date.now(), 2_147_483_647))
    const timer = window.setTimeout(expire, delay)
    const visibility = () => {
      if (document.visibilityState === 'visible') expire()
    }
    document.addEventListener('visibilitychange', visibility)
    return () => {
      window.clearTimeout(timer)
      document.removeEventListener('visibilitychange', visibility)
    }
  }, [authState, live, retryAuthentication, session])

  useEffect(() => {
    if (!live) return
    const revalidate = () => {
      if (sessionRef.current) void retryAuthentication()
    }
    const visibility = () => {
      if (document.visibilityState === 'visible') revalidate()
    }
    document.addEventListener('visibilitychange', visibility)
    window.addEventListener('pageshow', revalidate)
    return () => {
      document.removeEventListener('visibilitychange', visibility)
      window.removeEventListener('pageshow', revalidate)
    }
  }, [live, retryAuthentication])

  const hasPermission = useCallback((permission: AdministratorPermission, networkId?: string) => {
    if (!live) return true
    const current = sessionRef.current
    if (!current || !current.permissions.includes(permission)) return false
    if (networkId === undefined) return true
    return current.allNetworks || current.networkIds.includes(networkId)
  }, [live])

  const request = useCallback(async <T,>(path: string, options: RequestOptions = {}) => {
    if (!live) throw new Error('The demo console has no controller transport.')
    const current = sessionRef.current
    if (!current || authState !== 'authenticated') throw new ControllerRequestError(401, 'Sign in to continue.')
    const generation = authGenerationRef.current
    const method = (options.method ?? 'GET').toUpperCase()
    const headers = new Headers({ Accept: 'application/json' })
    if (options.body !== undefined) headers.set('Content-Type', 'application/json')
    if (!safeMethods.has(method)) {
      if (!csrfRef.current) throw new Error('The browser session has no CSRF token.')
      headers.set('X-Laneway-CSRF', csrfRef.current)
    }
    const response = await authFetch(path, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
    })
    if (authGenerationRef.current !== generation) throw new ControllerRequestError(409, 'The administrator session changed while the request was in progress.')
    if (!response.ok) {
      const message = await responseError(response)
      if (authGenerationRef.current !== generation) throw new ControllerRequestError(409, 'The administrator session changed while the error response was being read.')
      if (response.status === 401 && invalidateSession(generation, 'Your session expired. Sign in again.')) {
        notifyOtherTabs('logout', current.sessionId)
      }
      throw new ControllerRequestError(response.status, message)
    }
    if (!refreshSessionMetadata(response, generation)) {
      await reconcileCredentialCookieMutation()
      throw new ControllerRequestError(409, 'The administrator session changed while the request was in progress.')
    }
    if (response.status === 204) return undefined as T
    const body = await response.json() as T
    if (authGenerationRef.current !== generation) throw new ControllerRequestError(409, 'The administrator session changed while the response was being read.')
    return body
  }, [authState, invalidateSession, live, notifyOtherTabs, reconcileCredentialCookieMutation, refreshSessionMetadata])

  const reconcileInvalidSessionResponse = useCallback(async (generation: number, message: string, previousSessionId?: string) => {
    if (authGenerationRef.current !== generation) return
    clearSessionSecrets()
    sessionRef.current = null
    csrfRef.current = ''
    setSession(null)
    setAuthState('checking')
    resetInventory()
    try {
      const sessionResponse = await authFetch('/v1/admin/auth/session', { headers: { Accept: 'application/json' } })
      if (authGenerationRef.current !== generation) return
      if (sessionResponse.status === 401) {
        if (invalidateSession(generation, message) && previousSessionId) notifyOtherTabs('logout', previousSessionId)
        return
      }
      if (!sessionResponse.ok) throw new Error('Administrator session reconciliation failed.')
      const envelope = parseAdministratorSession(await sessionResponse.json())
      if (authGenerationRef.current !== generation) return
      const logoutResponse = await authFetch('/v1/admin/auth/logout', {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-Laneway-CSRF': envelope.csrfToken },
        body: '{}',
      })
      if (authGenerationRef.current !== generation) {
        await reconcileCredentialCookieMutation()
        return
      }
      if (logoutResponse.status !== 204 && logoutResponse.status !== 401) throw new Error('Administrator session cleanup failed.')
      if (invalidateSession(generation, message)) {
        notifyOtherTabs('logout', envelope.session.sessionId)
        if (previousSessionId && previousSessionId !== envelope.session.sessionId) notifyOtherTabs('logout', previousSessionId)
      }
    } catch {
      if (authGenerationRef.current !== generation) return
      clearSessionSecrets()
      authGenerationRef.current += 1
      sessionRef.current = null
      csrfRef.current = ''
      setSession(null)
      setAuthState('unavailable')
      setAuthError(`${message} Controller session cleanup could not be confirmed.`)
      setAuthPending(false)
      resetInventory()
    }
  }, [clearSessionSecrets, invalidateSession, notifyOtherTabs, reconcileCredentialCookieMutation, resetInventory])

  const signIn = useCallback(async (username: string, password: string) => {
    if (!live) return true
    restoreAbortRef.current?.abort()
    const generation = ++authGenerationRef.current
    clearSessionSecrets()
    sessionRef.current = null
    csrfRef.current = ''
    setSession(null)
    setAuthState('anonymous')
    setAuthPending(true)
    setAuthError('')
    resetInventory()
    try {
      const response = await authFetch('/v1/admin/auth/login', {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      })
      if (authGenerationRef.current !== generation) {
        await reconcileCredentialCookieMutation()
        return false
      }
      if (!response.ok) {
        if (response.status === 401) throw new ControllerRequestError(401, 'The username or password was rejected.')
        if (response.status === 429) throw new ControllerRequestError(429, 'Too many sign-in attempts. Try again later.')
        throw new ControllerRequestError(response.status, await responseError(response))
      }
      let envelope: SessionEnvelope
      try {
        const body = await response.json()
        if (authGenerationRef.current !== generation) {
          await reconcileCredentialCookieMutation()
          return false
        }
        envelope = parseAdministratorSession(body)
      } catch {
        if (authGenerationRef.current !== generation) {
          await reconcileCredentialCookieMutation()
          return false
        }
        await reconcileInvalidSessionResponse(generation, 'The sign-in response was invalid. Sign in again.')
        return false
      }
      if (authGenerationRef.current !== generation) return false
      const installed = installSession(envelope, generation)
      if (installed) notifyOtherTabs('session-changed', envelope.session.sessionId)
      return installed
    } catch (error) {
      if (authGenerationRef.current !== generation) {
        await reconcileCredentialCookieMutation()
        return false
      }
      setAuthState('anonymous')
      setAuthError(error instanceof Error ? error.message : 'Unable to sign in.')
      return false
    } finally {
      if (authGenerationRef.current === generation) setAuthPending(false)
    }
  }, [clearSessionSecrets, installSession, live, notifyOtherTabs, reconcileCredentialCookieMutation, reconcileInvalidSessionResponse, resetInventory])

  const rotateSession = useCallback(async () => {
    if (!live) return true
    const current = sessionRef.current
    if (!current || authState !== 'authenticated') return false
    const generation = authGenerationRef.current
    let completionGeneration = generation
    setAuthPending(true)
    setAuthError('')
    try {
      const response = await authFetch('/v1/admin/auth/session/rotate', {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-Laneway-CSRF': csrfRef.current },
        body: '{}',
      })
      if (authGenerationRef.current !== generation) {
        await reconcileCredentialCookieMutation()
        return false
      }
      if (!response.ok) {
        const message = await responseError(response)
        if (authGenerationRef.current !== generation) {
          await reconcileCredentialCookieMutation()
          return false
        }
        if (response.status === 401 && invalidateSession(generation, 'Your session expired. Sign in again.')) notifyOtherTabs('logout', current.sessionId)
        else setAuthError(message)
        return false
      }
      let envelope: SessionEnvelope
      try {
        envelope = parseAdministratorSession(await response.json())
      } catch {
        if (authGenerationRef.current !== generation) {
          await reconcileCredentialCookieMutation()
          return false
        }
        await reconcileInvalidSessionResponse(generation, 'The rotated session response was invalid. Sign in again.', current.sessionId)
        completionGeneration = authGenerationRef.current
        return false
      }
      if (authGenerationRef.current !== generation) {
        await reconcileCredentialCookieMutation()
        return false
      }
      clearSessionSecrets()
      const nextGeneration = ++authGenerationRef.current
      completionGeneration = nextGeneration
      const installed = installSession(envelope, nextGeneration)
      if (installed) notifyOtherTabs('session-changed', envelope.session.sessionId)
      return installed
    } catch (error) {
      if (authGenerationRef.current !== generation) {
        await reconcileCredentialCookieMutation()
        return false
      }
      setAuthError(error instanceof Error ? error.message : 'Unable to rotate the session.')
      return false
    } finally {
      if (authGenerationRef.current === completionGeneration) setAuthPending(false)
    }
  }, [authState, clearSessionSecrets, installSession, invalidateSession, live, notifyOtherTabs, reconcileCredentialCookieMutation, reconcileInvalidSessionResponse])

  const signOut = useCallback(async () => {
    if (!live) return true
    const current = sessionRef.current
    if (!current) return true
    const generation = authGenerationRef.current
    setAuthPending(true)
    setAuthError('')
    try {
      const response = await authFetch('/v1/admin/auth/logout', {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-Laneway-CSRF': csrfRef.current },
        body: '{}',
      })
      if (authGenerationRef.current !== generation) {
        await reconcileCredentialCookieMutation()
        return false
      }
      if (!response.ok && response.status !== 401) {
        const message = await responseError(response)
        if (authGenerationRef.current !== generation) {
          await reconcileCredentialCookieMutation()
          return false
        }
        setAuthError(message)
        return false
      }
    } catch {
      if (authGenerationRef.current !== generation) {
        await reconcileCredentialCookieMutation()
        return false
      }
      setAuthError('Sign out could not be confirmed. Try again before leaving this device.')
      return false
    } finally {
      if (authGenerationRef.current === generation) setAuthPending(false)
    }
    if (authGenerationRef.current !== generation) return false
    clearSessionSecrets()
    authGenerationRef.current += 1
    sessionRef.current = null
    csrfRef.current = ''
    setSession(null)
    setAuthState('anonymous')
    setAuthError('')
    resetInventory()
    notifyOtherTabs('logout', current.sessionId)
    return true
  }, [clearSessionSecrets, live, notifyOtherTabs, reconcileCredentialCookieMutation, resetInventory])

  const captureSessionBinding = useCallback((): AdministratorSessionBinding | null => {
    const current = sessionRef.current
    return current ? {
      sessionId: current.sessionId,
      generation: authGenerationRef.current,
      networkId: selectedNetworkIdRef.current,
      networkGeneration: networkGenerationRef.current,
    } : null
  }, [])

  const isSessionBindingCurrent = useCallback((binding: AdministratorSessionBinding) => {
    return authGenerationRef.current === binding.generation &&
      sessionRef.current?.sessionId === binding.sessionId &&
      selectedNetworkIdRef.current === binding.networkId &&
      networkGenerationRef.current === binding.networkGeneration
  }, [])

  const storeIssuedEnrollmentToken = useCallback((binding: AdministratorSessionBinding, value: IssuedEnrollmentToken) => {
    if (!isSessionBindingCurrent(binding)) return false
    issuedEnrollmentTokenRef.current = { binding, value }
    return true
  }, [isSessionBindingCurrent])

  const peekIssuedEnrollmentToken = useCallback(() => {
    const issued = issuedEnrollmentTokenRef.current
    return issued && isSessionBindingCurrent(issued.binding) ? issued : null
  }, [isSessionBindingCurrent])

  const clearIssuedEnrollmentToken = useCallback((binding: AdministratorSessionBinding) => {
    const issued = issuedEnrollmentTokenRef.current
    if (issued?.binding.generation === binding.generation && issued.binding.sessionId === binding.sessionId &&
      issued.binding.networkId === binding.networkId && issued.binding.networkGeneration === binding.networkGeneration) {
      issuedEnrollmentTokenRef.current = null
    }
  }, [])

  const takeIssuedEnrollmentToken = useCallback(() => {
    const issued = issuedEnrollmentTokenRef.current
    issuedEnrollmentTokenRef.current = null
    return issued && isSessionBindingCurrent(issued.binding) ? issued : null
  }, [isSessionBindingCurrent])

  const loadInventory = useCallback(async () => {
    if (!live || !sessionRef.current || !hasPermission('network.list')) return
    const requestId = ++inventoryRequestRef.current
    const generation = authGenerationRef.current
    const isCurrentRequest = () => requestId === inventoryRequestRef.current && generation === authGenerationRef.current
    setInventoryPending(true)
    setInventoryError('')
    try {
      const networkResult = await request<{ networks: ControllerNetwork[] }>('/v1/admin/networks?limit=100')
      if (!isCurrentRequest()) return
      const activeSession = sessionRef.current
      if (!activeSession || networkResult.networks.some((network) => !activeSession.allNetworks && !activeSession.networkIds.includes(network.network_id))) {
        throw new Error('Controller returned a network outside the administrator session scope.')
      }
      if (new Set(networkResult.networks.map((network) => network.network_id)).size !== networkResult.networks.length ||
        networkResult.networks.some((network) => !identityPattern.test(network.network_id))) {
        throw new Error('Controller returned invalid or duplicate network identifiers.')
      }
      const requestedNetworkId = selectedNetworkIdRef.current
      let network = requestedNetworkId === null ? null : networkResult.networks.find((candidate) => candidate.network_id === requestedNetworkId) ?? null
      if (requestedNetworkId !== null && !network) {
        networkGenerationRef.current += 1
        clearSessionSecrets()
        selectedNetworkIdRef.current = null
        setSelectedNetworkId(null)
      }
      if (!network && networkResult.networks.length === 1) {
        network = networkResult.networks[0]
        networkGenerationRef.current += 1
        selectedNetworkIdRef.current = network.network_id
        setSelectedNetworkId(network.network_id)
      }
      const globalAuditResult = hasPermission('audit.read_global')
        ? await request<{ events: ControllerAuditEvent[] }>('/v1/admin/audit?limit=250')
        : { events: [] }
      if (!isCurrentRequest()) return
      if (globalAuditResult.events.some((event) => event.actor_kind === 'recovery_grant' && !event.actor_id)) {
        throw new Error('Controller returned a recovery audit event without an actor identifier.')
      }
      if (!network) {
        setInventory({ ...emptyInventory, networks: networkResult.networks, auditEvents: globalAuditResult.events })
        return
      }
      const networkId = network.network_id
      const prefix = `/v1/admin/networks/${network.network_id}`
      const [nodeResult, routeResult, ruleResult, relayResult, certificateResult, auditResult] = await Promise.all([
        hasPermission('node.read', network.network_id) ? request<{ nodes: ControllerNode[] }>(`${prefix}/nodes?limit=1000`) : Promise.resolve({ nodes: [] }),
        hasPermission('route.read', network.network_id) ? request<{ routes: ControllerRoute[] }>(`${prefix}/routes?limit=1000`) : Promise.resolve({ routes: [] }),
        hasPermission('acl.read', network.network_id) ? request<{ acl_rules: ControllerACLRule[] }>(`${prefix}/acl-rules?limit=1000`) : Promise.resolve({ acl_rules: [] }),
        hasPermission('relay.read', network.network_id) ? request<{ relays: ControllerRelay[] }>(`${prefix}/relays?limit=1000`) : Promise.resolve({ relays: [] }),
        hasPermission('certificate.read', network.network_id) ? request<{ certificates: ControllerCertificate[] }>(`${prefix}/certificates?limit=1000`) : Promise.resolve({ certificates: [] }),
        !hasPermission('audit.read_global') && hasPermission('audit.read', network.network_id) ? request<{ events: ControllerAuditEvent[] }>(`${prefix}/audit?limit=250`) : Promise.resolve({ events: [] }),
      ])
      const foreignInventory = [
        ...nodeResult.nodes,
        ...routeResult.routes,
        ...ruleResult.acl_rules,
        ...relayResult.relays,
        ...certificateResult.certificates,
        ...auditResult.events,
      ].some((record) => record.network_id !== networkId)
      if (foreignInventory) throw new Error('Controller returned inventory outside the selected network scope.')
      const auditEvents = hasPermission('audit.read_global') ? globalAuditResult.events : auditResult.events
      if (auditEvents.some((event) => event.actor_kind === 'recovery_grant' && !event.actor_id)) {
        throw new Error('Controller returned a recovery audit event without an actor identifier.')
      }
      if (isCurrentRequest()) {
        setInventory({
          networks: networkResult.networks,
          network,
          nodes: nodeResult.nodes,
          routes: routeResult.routes,
          aclRules: ruleResult.acl_rules,
          relays: relayResult.relays,
          certificates: certificateResult.certificates,
          auditEvents,
        })
      }
    } catch (error) {
      if (isCurrentRequest()) setInventoryError(error instanceof Error ? error.message : 'Unable to load controller inventory.')
    } finally {
      if (isCurrentRequest()) setInventoryPending(false)
    }
  }, [clearSessionSecrets, hasPermission, live, request])

  const selectNetwork = useCallback((networkId: string) => {
    const current = inventory
    const network = current?.networks.find((candidate) => candidate.network_id === networkId)
    if (!current || !network || !sessionRef.current) return
    if (selectedNetworkIdRef.current !== networkId) networkGenerationRef.current += 1
    clearSessionSecrets()
    selectedNetworkIdRef.current = networkId
    setSelectedNetworkId(networkId)
    setInventory({ ...emptyInventory, networks: current.networks, network })
    setInventoryError('')
    void loadInventory()
  }, [clearSessionSecrets, inventory, loadInventory])

  const activeSessionId = session?.sessionId
  useEffect(() => {
    if (live && authState === 'authenticated' && activeSessionId) void loadInventory()
  }, [activeSessionId, authState, live, loadInventory])

  const value = useMemo<ControlPlaneContextValue>(() => ({
    live,
    authState,
    authenticated: !live || authState === 'authenticated',
    sessionPending: live && authState === 'checking',
    authPending,
    authError,
    session,
    inventory,
    inventoryPending,
    inventoryError,
    selectedNetworkId,
    selectNetwork,
    captureSessionBinding,
    storeIssuedEnrollmentToken,
    peekIssuedEnrollmentToken,
    clearIssuedEnrollmentToken,
    takeIssuedEnrollmentToken,
    isSessionBindingCurrent,
    signIn,
    signOut,
    retryAuthentication,
    rotateSession,
    hasPermission,
    refresh: loadInventory,
    request,
  }), [authError, authPending, authState, captureSessionBinding, clearIssuedEnrollmentToken, hasPermission, inventory, inventoryError, inventoryPending, isSessionBindingCurrent, live, loadInventory, peekIssuedEnrollmentToken, request, retryAuthentication, rotateSession, selectedNetworkId, selectNetwork, session, signIn, signOut, storeIssuedEnrollmentToken, takeIssuedEnrollmentToken])

  return <ControlPlaneContext.Provider value={value}>{children}</ControlPlaneContext.Provider>
}

export function useControlPlane() {
  const value = useContext(ControlPlaneContext)
  if (!value) throw new Error('useControlPlane must be used inside ControlPlaneProvider')
  return value
}
