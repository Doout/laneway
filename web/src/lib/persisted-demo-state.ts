import type { AccessRuleRecord, NodeRecord, RouteRecord, UserEnrollmentRecord } from './demo-data'
import { accessRules, nodes, routes, userEnrollments } from './demo-data'

export type NodeCapabilities = {
  publish: boolean
  accept: boolean
  exit: boolean
  relay: boolean
}

export type AttributedChange = {
  actedAt: string
  actedBy: string
  result: string
}

export type DemoNodeChange = AttributedChange & {
  capabilities?: NodeCapabilities
  record?: NodeRecord
}

export type DemoRouteChange = AttributedChange & {
  record: RouteRecord
}

export type DemoAccessRuleChange = AttributedChange & {
  record: AccessRuleRecord
}

export type DemoUserChange = AttributedChange & {
  record: UserEnrollmentRecord
}

export type DemoTokenChange = AttributedChange & {
  state: 'Revoked'
}

export type DemoCertificateChange = AttributedChange & {
  expires: string
  state: 'Rotation queued'
}

export type PersistedDemoState = {
  nodes: Record<string, DemoNodeChange>
  routes: Record<string, DemoRouteChange>
  accessRules: Record<string, DemoAccessRuleChange>
  users: Record<string, DemoUserChange>
  tokens: Record<string, DemoTokenChange>
  certificates: Record<string, DemoCertificateChange>
}

const STORAGE_KEY = 'laneway-console-demo-state-v2'
const LEGACY_STORAGE_KEY = 'laneway-console-demo-state-v1'

const emptyState = (): PersistedDemoState => ({
  nodes: {},
  routes: {},
  accessRules: {},
  users: {},
  tokens: {},
  certificates: {},
})

export function attributed(result: string): AttributedChange {
  return { actedAt: 'Aug 11, 2026 at 10:14 UTC', actedBy: 'Demo operator', result }
}

export function readDemoState(): PersistedDemoState {
  if (typeof window === 'undefined') return emptyState()
  try {
    // Version one could contain identity-bearing sample data from older builds.
    window.localStorage.removeItem(LEGACY_STORAGE_KEY)
    const value = window.localStorage.getItem(STORAGE_KEY)
    if (!value) return emptyState()
    const stored = JSON.parse(value) as Partial<PersistedDemoState>
    return {
      nodes: stored.nodes ?? {},
      routes: stored.routes ?? {},
      accessRules: stored.accessRules ?? {},
      users: stored.users ?? {},
      tokens: stored.tokens ?? {},
      certificates: stored.certificates ?? {},
    }
  } catch {
    return emptyState()
  }
}

export function updateDemoState(update: (current: PersistedDemoState) => PersistedDemoState) {
  const next = update(readDemoState())
  if (typeof window !== 'undefined') {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next))
    window.dispatchEvent(new CustomEvent('laneway-demo-state'))
  }
  return next
}

export function persistedNodes() {
  const changes = readDemoState().nodes
  const records = nodes.map(record => changes[record.id]?.record ?? record)
  const known = new Set(records.map(record => record.id))
  return [...records, ...Object.values(changes).flatMap(change => change.record && !known.has(change.record.id) ? [change.record] : [])]
}

export function persistedRoutes() {
  const changes = readDemoState().routes
  const records = routes.map(record => changes[record.id]?.record ?? record)
  const known = new Set(records.map(record => record.id))
  return [...records, ...Object.values(changes).flatMap(change => !known.has(change.record.id) ? [change.record] : [])]
}

export function persistedAccessRules() {
  const changes = readDemoState().accessRules
  const records = accessRules.map(record => changes[record.id]?.record ?? record)
  const known = new Set(records.map(record => record.id))
  return [...records, ...Object.values(changes).flatMap(change => !known.has(change.record.id) ? [change.record] : [])]
}

export function persistedUsers() {
  const changes = readDemoState().users
  const records = userEnrollments.map(record => changes[record.id]?.record ?? record)
  const known = new Set(records.map(record => record.id))
  return [...records, ...Object.values(changes).flatMap(change => !known.has(change.record.id) ? [change.record] : [])]
}
