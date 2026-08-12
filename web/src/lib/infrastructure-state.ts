import { useSyncExternalStore } from 'react'

export interface InfrastructureNetwork {
  id: string
  name: string
  addressPool: string
  ipv6Pool: string
  createdAt: string
  nodes: number
  connectedNodes: number
  routes: number
  healthyRoutes: number
  userEnrollments: number
  rememberedEnrollments: number
  connector: {
    id: string
    name: string
    sessions: string
    state: 'Connected' | 'Enrolled' | 'Offline'
  }
  connectors?: Array<{
    id: string
    name: string
    sessions: string
    state: 'Connected' | 'Enrolled' | 'Offline'
  }>
  configurationEpoch?: number
  lastAction: string
  updatedBy: string
  updatedAt: string
}

export interface InfrastructureRelay {
  id: string
  name: string
  endpoint: string
  networkId: string | 'all'
  sessions: number
  enabled: boolean
  reachable: boolean
  certificateDays: number
  lastProbe: string
  lastAction: string
  updatedBy: string
  updatedAt: string
  createdAt?: string
  configurationEpoch?: number
}

interface InfrastructureState {
  networks: InfrastructureNetwork[]
  relays: InfrastructureRelay[]
}

export const INFRASTRUCTURE_ACTOR = 'Demo operator'
const STORAGE_KEY = 'laneway.infrastructure.v2'
const LEGACY_STORAGE_KEY = 'laneway.infrastructure.v1'

const initialState: InfrastructureState = {
  networks: [
    {
      id: 'production',
      name: 'Production',
      addressPool: '100.88.0.0/24',
      ipv6Pool: 'fd7a:115c:a1e0::/64',
      createdAt: 'Jul 18, 2026',
      nodes: 11,
      connectedNodes: 9,
      routes: 7,
      healthyRoutes: 6,
      userEnrollments: 3,
      rememberedEnrollments: 2,
      connector: { id: 'nod_01J8ATLAS9GP', name: 'atlas-gateway', sessions: '6 direct · 1 relayed', state: 'Connected' },
      lastAction: 'Created',
      updatedBy: INFRASTRUCTURE_ACTOR,
      updatedAt: 'Jul 18, 2026 at 10:42 UTC',
    },
    {
      id: 'home',
      name: 'Home',
      addressPool: '100.88.1.0/24',
      ipv6Pool: 'fd7a:115c:a1e0:1::/64',
      createdAt: 'Jul 21, 2026',
      nodes: 4,
      connectedNodes: 4,
      routes: 3,
      healthyRoutes: 3,
      userEnrollments: 2,
      rememberedEnrollments: 2,
      connector: { id: 'nod_01J8HOME4D2', name: 'home-gateway', sessions: '3 direct', state: 'Connected' },
      lastAction: 'Created',
      updatedBy: INFRASTRUCTURE_ACTOR,
      updatedAt: 'Jul 21, 2026 at 08:15 UTC',
    },
    {
      id: 'lab',
      name: 'Lab',
      addressPool: '100.88.2.0/24',
      ipv6Pool: 'fd7a:115c:a1e0:2::/64',
      createdAt: 'Aug 2, 2026',
      nodes: 3,
      connectedNodes: 2,
      routes: 2,
      healthyRoutes: 1,
      userEnrollments: 1,
      rememberedEnrollments: 0,
      connector: { id: 'nod_01J8LAB2K7M', name: 'lab-gateway', sessions: '1 direct · 1 relayed', state: 'Connected' },
      lastAction: 'Created',
      updatedBy: INFRASTRUCTURE_ACTOR,
      updatedAt: 'Aug 2, 2026 at 14:03 UTC',
    },
  ],
  relays: [
    {
      id: 'rly_iad01',
      name: 'iad-relay-01',
      endpoint: 'iad.example.net:443',
      networkId: 'production',
      sessions: 1,
      enabled: true,
      reachable: true,
      certificateDays: 182,
      lastProbe: '8 seconds ago',
      lastAction: 'Health probe succeeded',
      updatedBy: 'Laneway controller',
      updatedAt: 'Aug 11, 2026 at 16:41 UTC',
    },
    {
      id: 'rly_fra02',
      name: 'fra-relay-02',
      endpoint: 'fra.example.net:443',
      networkId: 'production',
      sessions: 1,
      enabled: true,
      reachable: true,
      certificateDays: 91,
      lastProbe: '12 seconds ago',
      lastAction: 'Health probe succeeded',
      updatedBy: 'Laneway controller',
      updatedAt: 'Aug 11, 2026 at 16:41 UTC',
    },
    {
      id: 'rly_syd01',
      name: 'syd-relay-01',
      endpoint: 'syd.example.net:443',
      networkId: 'all',
      sessions: 0,
      enabled: true,
      reachable: true,
      certificateDays: 240,
      lastProbe: '21 seconds ago',
      lastAction: 'Health probe succeeded',
      updatedBy: 'Laneway controller',
      updatedAt: 'Aug 11, 2026 at 16:40 UTC',
    },
  ],
}

function readState(): InfrastructureState {
  if (typeof window === 'undefined') return initialState
  try {
    // Discard sample state that may retain identity labels from older builds.
    window.localStorage.removeItem(LEGACY_STORAGE_KEY)
    const value = window.localStorage.getItem(STORAGE_KEY)
    return value ? JSON.parse(value) as InfrastructureState : initialState
  } catch {
    return initialState
  }
}

let currentState = readState()
const listeners = new Set<() => void>()

function emit(nextState: InfrastructureState) {
  currentState = nextState
  if (typeof window !== 'undefined') window.localStorage.setItem(STORAGE_KEY, JSON.stringify(nextState))
  listeners.forEach((listener) => listener())
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function nowLabel() {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'UTC',
    timeZoneName: 'short',
  }).format(new Date())
}

function slugify(value: string) {
  const slug = value.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
  return slug || `network-${Date.now()}`
}

export function useInfrastructureState() {
  return useSyncExternalStore(subscribe, () => currentState, () => initialState)
}

export function addInfrastructureNetwork(input: { name: string; addressPool: string }) {
  const baseId = slugify(input.name)
  let id = baseId
  let suffix = 2
  while (currentState.networks.some((network) => network.id === id)) id = `${baseId}-${suffix++}`
  const network: InfrastructureNetwork = {
    id,
    name: input.name.trim(),
    addressPool: input.addressPool.trim(),
    ipv6Pool: 'Not configured',
    createdAt: nowLabel(),
    nodes: 0,
    connectedNodes: 0,
    routes: 0,
    healthyRoutes: 0,
    userEnrollments: 0,
    rememberedEnrollments: 0,
    connector: { id: 'none', name: 'No connector', sessions: 'No active sessions', state: 'Offline' },
    lastAction: 'Network created',
    updatedBy: INFRASTRUCTURE_ACTOR,
    updatedAt: nowLabel(),
  }
  emit({ ...currentState, networks: [...currentState.networks, network] })
  return network
}

export function deleteInfrastructureNetwork(networkId: string) {
  emit({
    networks: currentState.networks.filter((network) => network.id !== networkId),
    relays: currentState.relays.map((relay) => relay.networkId === networkId
      ? { ...relay, networkId: 'all', lastAction: 'Network assignment removed', updatedBy: INFRASTRUCTURE_ACTOR, updatedAt: nowLabel() }
      : relay),
  })
}

export function registerInfrastructureRelay(input: { name: string; endpoint: string; networkId: string | 'all'; enabled: boolean }) {
  const relay: InfrastructureRelay = {
    id: `rly_${slugify(input.name)}_${Date.now().toString(36)}`,
    name: input.name.trim(),
    endpoint: input.endpoint.trim(),
    networkId: input.networkId,
    sessions: 0,
    enabled: input.enabled,
    reachable: false,
    certificateDays: 365,
    lastProbe: input.enabled ? 'Awaiting first health probe' : 'Probes paused',
    lastAction: input.enabled ? 'Registered and enabled' : 'Registered disabled',
    updatedBy: INFRASTRUCTURE_ACTOR,
    updatedAt: nowLabel(),
  }
  emit({ ...currentState, relays: [...currentState.relays, relay] })
  return relay
}

export function setInfrastructureRelayEnabled(relayId: string, enabled: boolean) {
  emit({
    ...currentState,
    relays: currentState.relays.map((relay) => relay.id === relayId
      ? {
        ...relay,
        enabled,
        reachable: enabled ? relay.reachable : false,
        sessions: enabled ? relay.sessions : 0,
        lastProbe: enabled ? 'Health probe queued' : 'Probes paused',
        lastAction: enabled ? 'Relay enabled' : 'Relay disabled',
        updatedBy: INFRASTRUCTURE_ACTOR,
        updatedAt: nowLabel(),
      }
      : relay),
  })
}

export function rotateInfrastructureRelayCertificate(relayId: string) {
  emit({
    ...currentState,
    relays: currentState.relays.map((relay) => relay.id === relayId
      ? {
        ...relay,
        certificateDays: 365,
        lastAction: 'Relay certificate rotated',
        updatedBy: INFRASTRUCTURE_ACTOR,
        updatedAt: nowLabel(),
      }
      : relay),
  })
}
