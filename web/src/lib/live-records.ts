import type { AccessRuleRecord, NodeRecord, RouteRecord, UserEnrollmentRecord } from './demo-data'
import type { ControllerACLRule, ControllerNode, ControllerRoute } from './control-plane'

const SUBNET_ROUTER = 8
const EXIT_NODE = 16

function expired(timestamp?: number) {
  return timestamp !== undefined && timestamp <= Math.floor(Date.now() / 1000)
}

export function isPendingControllerRoute(route: ControllerRoute) {
  return route.state === 'advertised'
    && (route.valid_until_unix_seconds === undefined || !expired(route.valid_until_unix_seconds))
}
function nodeClass(node: ControllerNode): NodeRecord['enrollmentClass'] {
  if (node.enrollment_class === 'remembered') return 'Remembered user'
  if (node.enrollment_class === 'ephemeral') return 'Ephemeral user'
  return 'Durable'
}

function nodeCapabilityRoles(node: ControllerNode): NonNullable<NodeRecord['capabilityRoles']> {
  return [
    (node.enabled_capabilities & SUBNET_ROUTER) !== 0 ? 'Subnet router' : undefined,
    (node.enabled_capabilities & EXIT_NODE) !== 0 ? 'Exit node' : undefined,
  ].filter((role): role is NonNullable<NodeRecord['capabilityRoles']>[number] => role !== undefined)
}

export function controllerNodes(nodes: ControllerNode[]): NodeRecord[] {
  return nodes.map((node) => {
    const revoked = node.revoked_at_unix_seconds !== undefined
    const leaseExpired = node.enrollment_class === 'ephemeral' && expired(node.lease_expires_at_unix_seconds)
    return {
      id: node.node_id,
      networkId: node.network_id,
      name: node.name || node.node_id,
      enrollmentClass: nodeClass(node),
      capabilityRoles: nodeCapabilityRoles(node),
      addresses: [node.ipv4_address, node.ipv6_address].filter(Boolean).join(' · ') || 'Not assigned',
      state: leaseExpired ? 'Lease expired' : revoked ? 'Revoked' : 'Enrolled',
      tone: leaseExpired ? 'muted' : revoked ? 'danger' : 'positive',
    }
  })
}

export function controllerUsers(nodes: ControllerNode[], networkName: string): UserEnrollmentRecord[] {
  return nodes
    .filter((node) => node.enrollment_class === 'remembered' || node.enrollment_class === 'ephemeral')
    .map((node) => {
      const revoked = node.revoked_at_unix_seconds !== undefined
      const leaseExpired = node.enrollment_class === 'ephemeral' && expired(node.lease_expires_at_unix_seconds)
      const lease = node.lease_expires_at_unix_seconds
        ? new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(node.lease_expires_at_unix_seconds * 1000))
        : 'Until revoked'
      return {
        id: node.node_id,
        networkId: node.network_id,
        subject: node.name || node.node_id,
        enrollment: node.enrollment_class === 'ephemeral' ? 'Ephemeral' : 'Remembered',
        network: networkName,
        devices: 1,
        lease,
        state: leaseExpired ? 'Expired' : revoked ? 'Revoked' : 'Active',
        tone: leaseExpired ? 'muted' : revoked ? 'danger' : 'positive',
      }
    })
}

export function controllerRoutes(routes: ControllerRoute[], nodes: ControllerNode[]): RouteRecord[] {
  const nodeNames = new Map(nodes.map((node) => [node.node_id, node.name || node.node_id]))
  return routes.map((route) => {
    const routeExpired = (route.state === 'advertised' || route.state === 'approved')
      && route.valid_until_unix_seconds !== undefined
      && expired(route.valid_until_unix_seconds)
    const state = isPendingControllerRoute(route) ? 'Pending approval' : routeExpired ? 'Expired' : route.state === 'approved' ? 'Approved' : route.state === 'withdrawn' ? 'Withdrawn' : 'Rejected'
    return {
      id: route.route_id,
      networkId: route.network_id,
      name: route.kind === 'exit' ? `Exit via ${nodeNames.get(route.node_id) ?? route.node_id}` : route.prefix,
      destination: route.prefix,
      via: nodeNames.get(route.node_id) ?? route.node_id,
      mode: route.mode === 'routed' ? 'Routed' : route.mode === 'nat' ? 'NAT' : 'None',
      metric: route.metric,
      state,
      tone: state === 'Approved' ? 'positive' : state === 'Pending approval' ? 'warning' : state === 'Expired' || state === 'Withdrawn' ? 'muted' : 'danger',
    }
  })
}

function selectorSummary(selector: Record<string, unknown>) {
  const destination = selector.destination_prefixes
  if (Array.isArray(destination) && destination.length > 0) return `${destination.length} destination prefix${destination.length === 1 ? '' : 'es'}`
  const nodes = selector.destination_node_ids
  if (Array.isArray(nodes) && nodes.length > 0) return `${nodes.length} destination node${nodes.length === 1 ? '' : 's'}`
  return 'Controller traffic selector'
}

export function controllerRules(rules: ControllerACLRule[]): AccessRuleRecord[] {
  return rules.map((rule) => ({
    id: rule.rule_id,
    networkId: rule.network_id,
    priority: rule.priority,
    name: rule.description.trim() || `${rule.action === 'accept' ? 'Allow' : 'Deny'} rule ${rule.priority}`,
    rawDescription: rule.description,
    action: rule.action === 'accept' ? 'Allow' : 'Deny',
    selector: selectorSummary(rule.selector),
    target: 'Controller-evaluated traffic',
    state: rule.enabled ? 'Enabled' : 'Disabled',
    tone: rule.enabled ? 'positive' : 'muted',
  }))
}
