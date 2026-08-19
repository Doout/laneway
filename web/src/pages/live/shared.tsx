import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Link2, MonitorDot, Network, TriangleAlert } from 'lucide-react'
import { Button, Callout, EmptyState, FilterSelect, Toolbar } from '../../components/ui'
import type { ControllerACLRule, ControllerAuditEvent, ControllerCertificate, ControllerNode, ControllerRoute } from '../../lib/control-plane'

export function time(seconds?: number) {
  return seconds ? new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(seconds * 1000)) : 'Not recorded'
}

function timestampExpired(seconds?: number) {
  return seconds !== undefined && seconds <= Math.floor(Date.now() / 1000)
}

export function nodeState(node: ControllerNode) {
  const leaseExpired = node.enrollment_class === 'ephemeral' && timestampExpired(node.lease_expires_at_unix_seconds)
  if (leaseExpired) return { label: 'Lease expired', tone: 'muted' as const, inactive: true }
  if (node.revoked_at_unix_seconds !== undefined) return { label: 'Revoked', tone: 'danger' as const, inactive: true }
  return { label: 'Enrolled', tone: 'positive' as const, inactive: false }
}

export function routeMode(mode: ControllerRoute['mode']) {
  switch (mode) {
    case 'none': return 'None'
    case 'nat': return 'NAT'
    case 'routed': return 'Routed'
    default: {
      const exhaustive: never = mode
      return exhaustive
    }
  }
}

export function routeState(route: ControllerRoute) {
  if ((route.state === 'advertised' || route.state === 'approved') && timestampExpired(route.valid_until_unix_seconds)) {
    return { label: 'Expired', tone: 'muted' as const, actionable: false }
  }
  if (route.state === 'advertised') return { label: 'Advertised', tone: 'warning' as const, actionable: true }
  if (route.state === 'approved') return { label: 'Approved', tone: 'positive' as const, actionable: true }
  if (route.state === 'withdrawn') return { label: 'Withdrawn', tone: 'muted' as const, actionable: false }
  return { label: 'Rejected', tone: 'danger' as const, actionable: false }
}

export function certificateState(
  certificate: Pick<ControllerCertificate, 'not_before_unix_seconds' | 'not_after_unix_seconds' | 'revoked_at_unix_seconds'>,
  nowUnixSeconds = Math.floor(Date.now() / 1000),
) {
  if (certificate.revoked_at_unix_seconds !== undefined) return { label: 'Revoked', tone: 'danger' as const }
  if (nowUnixSeconds < certificate.not_before_unix_seconds) return { label: 'Not yet valid', tone: 'warning' as const }
  if (nowUnixSeconds >= certificate.not_after_unix_seconds) return { label: 'Expired', tone: 'muted' as const }
  return { label: 'Valid', tone: 'positive' as const }
}

export function aclRuleLabel(rule: ControllerACLRule) {
  return rule.description.trim() || `${rule.action === 'accept' ? 'Allow' : 'Deny'} rule ${rule.priority}`
}

export function auditActor(event: Pick<ControllerAuditEvent, 'actor_kind' | 'actor_id'>) {
  if (event.actor_kind === 'system') return 'System'
  if (event.actor_kind === 'unauthenticated') return 'Unauthenticated'
  if (event.actor_kind === 'legacy_unknown') return 'Legacy actor'
  const label = event.actor_kind === 'administrator' ? 'Administrator' : event.actor_kind === 'service_principal' ? 'Service principal' : event.actor_kind === 'recovery_grant' ? 'Recovery grant' : 'Node'
  return event.actor_id ? `${label} ${event.actor_id}` : label
}

export function routePurpose(route: ControllerRoute) {
  return route.kind === 'exit' ? 'Internet access' : 'Private destination'
}

export function routeModeDescription(mode: ControllerRoute['mode']) {
  if (mode === 'nat') return 'Translate addresses'
  if (mode === 'routed') return 'Preserve source addresses'
  return 'No address translation'
}

function decodePrefix(value: unknown) {
  if (!value || typeof value !== 'object') return undefined
  const prefix = value as Record<string, unknown>
  if (typeof prefix.address !== 'string' || typeof prefix.prefix_length !== 'number') return undefined
  try {
    const bytes = Array.from(atob(prefix.address), character => character.charCodeAt(0))
    if (bytes.length === 4) return `${bytes.join('.')}/${prefix.prefix_length}`
  } catch { /* Keep unfamiliar selector encodings out of the primary UX. */ }
  return undefined
}

export function selectorDestination(rule: ControllerACLRule) {
  const prefixes = Array.isArray(rule.selector.destination_prefixes) ? rule.selector.destination_prefixes : []
  const prefix = decodePrefix(prefixes[0])
  return prefix ?? (prefixes.length ? 'A configured destination' : 'Any destination')
}

export function selectorProtocol(rule: ControllerACLRule) {
  const value = typeof rule.selector.ip_protocol === 'string' ? rule.selector.ip_protocol.replace('IP_PROTOCOL_', '') : 'ANY'
  const ports = Array.isArray(rule.selector.destination_ports)
    ? rule.selector.destination_ports.map((candidate) => {
      if (!candidate || typeof candidate !== 'object') return undefined
      const port = candidate as Record<string, unknown>
      if (typeof port.first !== 'number' || typeof port.last !== 'number') return undefined
      return port.first === port.last ? String(port.first) : `${port.first}-${port.last}`
    }).filter(Boolean).join(', ')
    : ''
  return value === 'ANY' ? 'Any service' : `${value}${ports ? ` · ${ports}` : ''}`
}

export function selectorSource(rule: ControllerACLRule) {
  const nodeIds = Array.isArray(rule.selector.source_node_ids) ? rule.selector.source_node_ids : []
  const prefixes = Array.isArray(rule.selector.source_prefixes) ? rule.selector.source_prefixes : []
  if (nodeIds.length === 1) return 'One selected node'
  if (nodeIds.length > 1) return `${nodeIds.length} selected nodes`
  if (prefixes.length) return prefixes.length === 1 ? 'One source range' : `${prefixes.length} source ranges`
  return 'Any enrolled node'
}

export function accessRuleSummary(rule: ControllerACLRule) {
  return `${selectorSource(rule)} → ${selectorDestination(rule)} · ${selectorProtocol(rule)}`
}

function readableRouteName(value: string) {
  const name = value.replace(/^laneway-connector-/i, '').trim()
  if (name.toLowerCase() === 'ibmcloud') return 'IBM Cloud'
  return name.split('-').filter(Boolean).map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(' ')
}

export function accessRulePresentation(rule: ControllerACLRule) {
  const label = aclRuleLabel(rule)
  const managedRoute = /^managed route\s+(\S+)\s+via\s+(\S+)(?:\s+for\s+(.+))?$/i.exec(label)
  if (!managedRoute) return { title: label, detail: accessRuleSummary(rule) }

  const [, destination, connector, subject] = managedRoute
  return {
    title: `${destination} through ${readableRouteName(connector)}`,
    detail: `${subject ? `For ${subject.trim()} · ` : ''}${selectorProtocol(rule)}`,
  }
}

export function ipv4PrefixSelector(prefix: string, protocol: string, ports: string) {
  const [address, prefixLength] = prefix.split('/')
  const bytes = address.split('.').map(Number)
  const selector: Record<string, unknown> = {
    destination_prefixes: [{ address: btoa(String.fromCharCode(...bytes)), prefix_length: Number(prefixLength) }],
    ip_protocol: `IP_PROTOCOL_${protocol}`,
  }
  if ((protocol === 'TCP' || protocol === 'UDP') && ports.trim()) {
    selector.destination_ports = ports.split(',').map((entry) => {
      const [first, last] = entry.trim().split('-').map(Number)
      return { first, last: last ?? first }
    })
  }
  return selector
}

export function validPorts(value: string) {
  if (!value.trim()) return true
  return value.split(',').every((entry) => {
    const [first, last, extra] = entry.trim().split('-')
    if (extra !== undefined || !/^\d+$/.test(first)) return false
    const start = Number(first)
    if (start < 1 || start > 65535) return false
    if (last === undefined) return true
    return /^\d+$/.test(last) && Number(last) >= start && Number(last) <= 65535
  })
}

export function ErrorMessage({ value }: { value: string }) {
  return value ? <div role="alert"><Callout tone="danger">{value}</Callout></div> : null
}

export function Missing({ title, back }: { title: string; back: string }) {
  return <EmptyState icon={<TriangleAlert />} title={title} action={<Button to={back} variant="primary">Back</Button>} />
}

export type RecordVisibility = 'current' | 'all'
export type NetworkWorkspaceView = 'networks' | 'nodes' | 'connectivity'
export const subnetRouterCapability = 1 << 3
export const exitNodeCapability = 1 << 4
export const emptyNodes: ControllerNode[] = []

export function VisibilityToolbar({ value, onChange, currentLabel, visible, total, children }: {
  value: RecordVisibility
  onChange: (value: RecordVisibility) => void
  currentLabel: string
  visible: number
  total: number
  children?: ReactNode
}) {
  return <Toolbar filters={<>
    <FilterSelect label="Record visibility" value={value} onChange={(next) => onChange(next as RecordVisibility)}>
      <option value="current">{currentLabel}</option>
      <option value="all">All records</option>
    </FilterSelect>
    <span className="inventory-result-count" aria-live="polite">{visible} of {total} shown</span>
  </>}>{children}</Toolbar>
}

export function SummaryStrip({ label, items }: { label: string; items: Array<{ label: string; value: ReactNode; detail?: string; tone?: 'positive' | 'warning' | undefined }> }) {
  return <section className="summary-strip" aria-label={label}>{items.map((item) => <div key={item.label} className={item.tone ? `summary-strip__item is-${item.tone}` : 'summary-strip__item'}><span>{item.label}</span><strong>{item.value}</strong>{item.detail ? <small>{item.detail}</small> : null}</div>)}</section>
}

export function DashboardEmpty({ icon, title, description }: { icon: ReactNode; title: string; description?: string }) {
  return <div className="dashboard-empty"><span aria-hidden="true">{icon}</span><div><strong>{title}</strong>{description ? <p>{description}</p> : null}</div></div>
}

export function NetworkWorkspaceTabs({ view, networks, nodes, connections }: { view: NetworkWorkspaceView; networks: number; nodes: number; connections?: number }) {
  const items: Array<{ id: NetworkWorkspaceView; label: string; count: ReactNode; icon: ReactNode }> = [
    { id: 'networks', label: 'Networks', count: networks, icon: <Network size={15} /> },
    { id: 'nodes', label: 'Nodes', count: nodes, icon: <MonitorDot size={15} /> },
    { id: 'connectivity', label: 'Connectivity', count: connections ?? '—', icon: <Link2 size={15} /> },
  ]
  return <nav className="network-workspace-tabs" aria-label="Network workspace views">{items.map((item) => <Link key={item.id} to={item.id === 'networks' ? '/networks' : `/networks?view=${item.id}`} aria-current={view === item.id ? 'page' : undefined}><span aria-hidden="true">{item.icon}</span><span>{item.label}</span><em aria-hidden="true">{item.count}</em></Link>)}</nav>
}
