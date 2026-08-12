import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type PropsWithChildren } from 'react'

const TOKEN_KEY = 'laneway-console-admin-token'
const OPERATOR_KEY = 'laneway-console-operator'

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
  network_id: string
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

type RequestOptions = Omit<RequestInit, 'body'> & { body?: unknown }

type ControlPlaneContextValue = {
  live: boolean
  authenticated: boolean
  sessionPending: boolean
  authPending: boolean
  authError: string
  operator: string
  inventory: ControllerInventory | null
  inventoryPending: boolean
  inventoryError: string
  signIn: (operator: string, token: string) => Promise<boolean>
  signOut: () => void
  refresh: () => Promise<void>
  request: <T>(path: string, options?: RequestOptions) => Promise<T>
}

const emptyInventory: ControllerInventory = {
  networks: [], network: null, nodes: [], routes: [], aclRules: [], relays: [], certificates: [], auditEvents: [],
}

const ControlPlaneContext = createContext<ControlPlaneContextValue | null>(null)

export function controllerOrigin() {
  const configured = import.meta.env.VITE_LANEWAY_API_ORIGIN?.trim()
  return configured ? configured.replace(/\/+$/, '') : window.location.origin
}

export function parseConsoleBuildMode(value: unknown): 'live' | 'demo' {
  if (value === 'live' || value === 'demo') return value
  throw new Error(`Unsupported console build mode: ${String(value)}`)
}

function isLiveMode() {
  return parseConsoleBuildMode(import.meta.env.MODE) === 'live'
}

async function responseError(response: Response) {
  try {
    const body = await response.json() as { error?: string; message?: string; detail?: string }
    return body.error || body.message || body.detail || `Controller returned ${response.status}`
  } catch {
    return `Controller returned ${response.status}`
  }
}

export function ControlPlaneProvider({ children }: PropsWithChildren) {
  const live = isLiveMode()
  const [restoreToken] = useState(() => live ? window.sessionStorage.getItem(TOKEN_KEY) ?? '' : '')
  const [token, setToken] = useState('')
  const [operator, setOperator] = useState('')
  const [sessionPending, setSessionPending] = useState(() => Boolean(restoreToken))
  const [authPending, setAuthPending] = useState(false)
  const [authError, setAuthError] = useState('')
  const [inventory, setInventory] = useState<ControllerInventory | null>(live ? null : emptyInventory)
  const [inventoryPending, setInventoryPending] = useState(false)
  const [inventoryError, setInventoryError] = useState('')
  const inventoryRequestRef = useRef(0)

  const clearSession = useCallback((expectedToken?: string) => {
    if (expectedToken !== undefined && window.sessionStorage.getItem(TOKEN_KEY) !== expectedToken) return false
    inventoryRequestRef.current += 1
    window.sessionStorage.removeItem(TOKEN_KEY)
    window.sessionStorage.removeItem(OPERATOR_KEY)
    setToken('')
    setOperator('')
    setSessionPending(false)
    setInventory(live ? null : emptyInventory)
    setInventoryPending(false)
    setInventoryError('')
    return true
  }, [live])

  useEffect(() => {
    if (!live) return
    if (!restoreToken) {
      // A label has no meaning without an authenticated controller session.
      window.sessionStorage.removeItem(OPERATOR_KEY)
      return
    }

    const controller = new AbortController()
    void (async () => {
      try {
        const response = await fetch(`${controllerOrigin()}/v1/admin/networks?limit=1`, {
          headers: { Accept: 'application/json', Authorization: `Bearer ${restoreToken}` },
          signal: controller.signal,
        })
        if (!response.ok) {
          if (response.status === 401) {
            if (clearSession(restoreToken)) setAuthError('The saved controller session expired. Sign in again.')
            return
          }
          throw new Error(await responseError(response))
        }
        await response.json()
        if (controller.signal.aborted || window.sessionStorage.getItem(TOKEN_KEY) !== restoreToken) return
        const restoredOperator = window.sessionStorage.getItem(OPERATOR_KEY)?.trim() || ''
        setToken(restoreToken)
        setOperator(restoredOperator)
      } catch (error) {
        if (controller.signal.aborted || window.sessionStorage.getItem(TOKEN_KEY) !== restoreToken) return
        setAuthError(error instanceof Error ? error.message : 'Unable to restore the controller session.')
      } finally {
        if (!controller.signal.aborted && window.sessionStorage.getItem(TOKEN_KEY) === restoreToken) setSessionPending(false)
      }
    })()
    return () => controller.abort()
  }, [clearSession, live, restoreToken])

  const request = useCallback(async <T,>(path: string, options: RequestOptions = {}) => {
    if (live && !token) throw new Error('Sign in with the controller administrator token to continue.')
    const headers = new Headers(options.headers)
    headers.set('Accept', 'application/json')
    if (options.body !== undefined) headers.set('Content-Type', 'application/json')
    if (live) headers.set('Authorization', `Bearer ${token}`)
    const response = await fetch(`${controllerOrigin()}${path}`, {
      ...options,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    })
    if (!response.ok) {
      const error = new Error(await responseError(response))
      if (live && response.status === 401) clearSession(token)
      throw error
    }
    if (response.status === 204) return undefined as T
    return response.json() as Promise<T>
  }, [clearSession, live, token])

  const loadInventory = useCallback(async (activeToken = token) => {
    if (!live || !activeToken || window.sessionStorage.getItem(TOKEN_KEY) !== activeToken) return
    const requestId = ++inventoryRequestRef.current
    const isCurrentRequest = () => requestId === inventoryRequestRef.current
      && window.sessionStorage.getItem(TOKEN_KEY) === activeToken
    setInventoryPending(true)
    setInventoryError('')
    try {
      const headers = { Accept: 'application/json', Authorization: `Bearer ${activeToken}` }
      const get = async <T,>(path: string) => {
        const response = await fetch(`${controllerOrigin()}${path}`, { headers })
        if (!response.ok) {
          const error = new Error(await responseError(response))
          if (response.status === 401) clearSession(activeToken)
          throw error
        }
        return response.json() as Promise<T>
      }
      const networkResult = await get<{ networks: ControllerNetwork[] }>('/v1/admin/networks?limit=100')
      if (!isCurrentRequest()) return
      if (networkResult.networks.length > 1) {
        setInventory(null)
        setInventoryError('This console supports one network. Use the CLI for multi-network management.')
        return
      }
      const network = networkResult.networks[0] ?? null
      if (!network) {
        setInventory({ ...emptyInventory, networks: networkResult.networks })
        return
      }
      const prefix = `/v1/admin/networks/${network.network_id}`
      const [nodeResult, routeResult, ruleResult, relayResult, certificateResult, auditResult] = await Promise.all([
        get<{ nodes: ControllerNode[] }>(`${prefix}/nodes?limit=1000`),
        get<{ routes: ControllerRoute[] }>(`${prefix}/routes?limit=1000`),
        get<{ acl_rules: ControllerACLRule[] }>(`${prefix}/acl-rules?limit=1000`),
        get<{ relays: ControllerRelay[] }>(`${prefix}/relays?limit=1000`),
        get<{ certificates: ControllerCertificate[] }>(`${prefix}/certificates?limit=1000`),
        get<{ events: ControllerAuditEvent[] }>(`${prefix}/audit?limit=250`),
      ])
      if (isCurrentRequest()) {
        setInventory({
          networks: networkResult.networks,
          network,
          nodes: nodeResult.nodes,
          routes: routeResult.routes,
          aclRules: ruleResult.acl_rules,
          relays: relayResult.relays,
          certificates: certificateResult.certificates,
          auditEvents: auditResult.events,
        })
      }
    } catch (error) {
      const inventoryFailure = error instanceof Error ? error : new Error('Unable to load controller inventory.')
      if (isCurrentRequest()) setInventoryError(inventoryFailure.message)
    } finally {
      if (isCurrentRequest()) setInventoryPending(false)
    }
  }, [clearSession, live, token])

  useEffect(() => {
    if (live && token) void loadInventory()
  }, [live, loadInventory, token])

  const signIn = useCallback(async (nextOperator: string, nextToken: string) => {
    const cleanOperator = nextOperator.trim()
    const cleanToken = nextToken.trim()
    setAuthError('')
    if (!cleanToken) {
      setAuthError(live ? 'Enter the controller administrator token.' : 'Enter the demo administrator token.')
      return false
    }
    setAuthPending(true)
    try {
      if (live) {
        const response = await fetch(`${controllerOrigin()}/v1/admin/networks?limit=1`, {
          headers: { Accept: 'application/json', Authorization: `Bearer ${cleanToken}` },
        })
        if (!response.ok) throw new Error(response.status === 401 ? 'The administrator token was rejected.' : await responseError(response))
        await response.json()
        inventoryRequestRef.current += 1
        window.sessionStorage.setItem(TOKEN_KEY, cleanToken)
        if (cleanOperator) window.sessionStorage.setItem(OPERATOR_KEY, cleanOperator)
        else window.sessionStorage.removeItem(OPERATOR_KEY)
        setInventory(null)
        setInventoryPending(false)
        setInventoryError('')
        setToken(cleanToken)
      }
      setSessionPending(false)
      setAuthError('')
      setOperator(cleanOperator)
      return true
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : 'Unable to sign in to the controller.')
      return false
    } finally {
      setAuthPending(false)
    }
  }, [live])

  const signOut = useCallback(() => {
    clearSession()
    setAuthError('')
  }, [clearSession])

  const value = useMemo<ControlPlaneContextValue>(() => ({
    live,
    authenticated: !live || Boolean(token),
    sessionPending,
    authPending,
    authError,
    operator,
    inventory,
    inventoryPending,
    inventoryError,
    signIn,
    signOut,
    refresh: loadInventory,
    request,
  }), [authError, authPending, inventory, inventoryError, inventoryPending, live, loadInventory, operator, request, sessionPending, signIn, signOut, token])

  return <ControlPlaneContext.Provider value={value}>{children}</ControlPlaneContext.Provider>
}

export function useControlPlane() {
  const value = useContext(ControlPlaneContext)
  if (!value) throw new Error('useControlPlane must be used inside ControlPlaneProvider')
  return value
}
