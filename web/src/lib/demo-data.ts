export type StateTone = 'positive' | 'warning' | 'danger' | 'muted'

export interface NodeRecord {
  id: string
  name: string
  enrollmentClass: 'Connector' | 'Durable' | 'Exit node' | 'Remembered user' | 'Ephemeral user'
  capabilityRoles?: Array<'Subnet router' | 'Exit node'>
  addresses: string
  lastSeen?: string
  state: string
  tone: StateTone
}

export const nodes: NodeRecord[] = [
  { id: 'nod_01J8ATLAS9GP', name: 'atlas-gateway', enrollmentClass: 'Connector', addresses: '100.88.0.4 · fd7a::4', lastSeen: 'Just now', state: 'Connected', tone: 'positive' },
  { id: 'nod_01J8CLIENT19', name: 'operator-laptop', enrollmentClass: 'Durable', addresses: '100.88.0.19', lastSeen: '2 min ago', state: 'Connected', tone: 'positive' },
  { id: 'nod_01J8OPS7F3A', name: 'ops-session-7f3a', enrollmentClass: 'Remembered user', addresses: '100.88.0.27', lastSeen: '14 min ago', state: 'Connected', tone: 'positive' },
  { id: 'nod_01J8FRAEXIT', name: 'fra-exit-01', enrollmentClass: 'Exit node', addresses: '100.88.0.12', lastSeen: '1 hr ago', state: 'Relay fallback', tone: 'warning' },
  { id: 'nod_01J8ORACLE9', name: 'legacy-oracle', enrollmentClass: 'Connector', addresses: '100.88.0.9', lastSeen: '4 days ago', state: 'Offline', tone: 'danger' },
]

export interface UserEnrollmentRecord {
  id: string
  subject: string
  enrollment: 'Remembered' | 'Ephemeral'
  network: string
  devices: number
  lease: string
  state: string
  tone: StateTone
}

export const userEnrollments: UserEnrollmentRecord[] = [
  { id: 'usr_01J8PRIMARY4', subject: 'Platform operator', enrollment: 'Remembered', network: 'Production', devices: 2, lease: '28 days', state: 'Active', tone: 'positive' },
  { id: 'usr_01J8TEMPUSER', subject: 'Temporary operator', enrollment: 'Ephemeral', network: 'Production', devices: 1, lease: '42 min', state: 'Active', tone: 'positive' },
  { id: 'usr_01J8IRTEAM', subject: 'Incident response', enrollment: 'Ephemeral', network: 'All', devices: 0, lease: 'Expired', state: 'Expired', tone: 'muted' },
]

export interface RouteRecord {
  id: string
  name: string
  destination: string
  via: string
  mode: 'None' | 'NAT' | 'Routed'
  metric: number
  state: string
  tone: StateTone
}

export const routes: RouteRecord[] = [
  { id: 'rte_01J8PROD16', name: 'Production services', destination: '10.24.0.0/16', via: 'atlas-gateway', mode: 'NAT', metric: 100, state: 'Healthy', tone: 'positive' },
  { id: 'rte_01J8KUBEAPI', name: 'Kubernetes API', destination: '10.24.8.10/32', via: 'atlas-gateway', mode: 'Routed', metric: 80, state: 'Pending approval', tone: 'warning' },
  { id: 'rte_01J8HOMELAB', name: 'Home lab', destination: '192.168.50.0/24', via: 'home-pi', mode: 'NAT', metric: 100, state: 'Healthy', tone: 'positive' },
  { id: 'rte_01J8FRAEXIT', name: 'Frankfurt exit', destination: '0.0.0.0/0', via: 'fra-exit-01', mode: 'NAT', metric: 220, state: 'Relay fallback', tone: 'warning' },
]

export interface AccessRuleRecord {
  id: string
  priority: number
  name: string
  action: 'Allow' | 'Deny'
  selector: string
  target: string
  state: string
  tone: StateTone
}

export const accessRules: AccessRuleRecord[] = [
  { id: 'acl_01J8EXPIRED', priority: 10, name: 'Block expired responders', action: 'Deny', selector: 'enrollment:expired', target: 'All routes', state: 'Enabled', tone: 'positive' },
  { id: 'acl_01J8PRODOPS', priority: 100, name: 'Production operators', action: 'Allow', selector: 'subject:platform-on-call', target: 'Production routes', state: 'Enabled', tone: 'positive' },
  { id: 'acl_01J8DBREAD', priority: 120, name: 'Database read-only', action: 'Allow', selector: 'subject:analytics', target: '10.42.18.0/24', state: 'Enabled', tone: 'positive' },
  { id: 'acl_01J8LABTEMP', priority: 500, name: 'Temporary lab access', action: 'Allow', selector: 'enrollment:ephemeral', target: 'Lab network', state: 'Disabled', tone: 'muted' },
]

export const auditEvents = [
  { id: 'evt_01J8APRVD42', time: 'Today, 09:42', actor: 'operator', action: 'Route approved', target: 'Production services', outcome: 'Succeeded', tone: 'positive' as const },
  { id: 'evt_01J8USERTOK', time: 'Today, 09:31', actor: 'operator', action: 'User token issued', target: 'Platform on-call', outcome: 'Succeeded', tone: 'positive' as const },
  { id: 'evt_01J8RELAYFL', time: 'Today, 09:13', actor: 'controller', action: 'Relay probe failed', target: 'fra-relay-02', outcome: 'Recovered', tone: 'warning' as const },
  { id: 'evt_01J8RENEWED', time: 'Yesterday, 18:07', actor: 'atlas-gateway', action: 'Route renewed', target: 'Production services', outcome: 'Succeeded', tone: 'positive' as const },
  { id: 'evt_01J8REVOKED', time: 'Yesterday, 16:22', actor: 'operator', action: 'Node revoked', target: 'contractor-laptop', outcome: 'Succeeded', tone: 'positive' as const },
]
