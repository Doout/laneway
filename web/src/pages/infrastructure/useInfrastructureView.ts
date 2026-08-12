import { useControlPlane } from '../../lib/control-plane'
import { useInfrastructureState, type InfrastructureNetwork, type InfrastructureRelay } from '../../lib/infrastructure-state'

const SUBNET_ROUTER = 8

function dateLabel(seconds: number) {
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(seconds * 1000))
}

export function useInfrastructureView() {
  const demo = useInfrastructureState()
  const control = useControlPlane()
  if (!control.live) return { ...control, networks: demo.networks, relays: demo.relays }

  const source = control.inventory
  const networks: InfrastructureNetwork[] = (source?.network ? [source.network] : []).map((network) => {
    const nodes = (source?.nodes ?? []).filter((node) => node.network_id === network.network_id)
    const routes = (source?.routes ?? []).filter((route) => route.network_id === network.network_id
      && route.state !== 'withdrawn'
      && route.state !== 'rejected'
      && (!route.valid_until_unix_seconds || route.valid_until_unix_seconds > Math.floor(Date.now() / 1000)))
    const connectors = nodes.filter((node) => !node.revoked_at_unix_seconds && (node.enabled_capabilities & SUBNET_ROUTER) !== 0)
    const connector = connectors[0]
    return {
      id: network.network_id,
      name: network.name,
      addressPool: network.ipv4_pool,
      ipv6Pool: network.ipv6_pool || 'Not configured',
      createdAt: dateLabel(network.created_at_unix_seconds),
      nodes: nodes.length,
      connectedNodes: nodes.filter((node) => !node.revoked_at_unix_seconds).length,
      routes: routes.length,
      healthyRoutes: routes.filter((route) => route.state === 'approved').length,
      userEnrollments: nodes.filter((node) => node.enrollment_class === 'remembered' || node.enrollment_class === 'ephemeral').length,
      rememberedEnrollments: nodes.filter((node) => node.enrollment_class === 'remembered').length,
      connector: connector
        ? { id: connector.node_id, name: connector.name, sessions: 'Session telemetry unavailable', state: 'Enrolled' as const }
        : { id: 'none', name: 'No connector', sessions: 'Not applicable', state: 'Offline' as const },
      connectors: connectors.map((record) => ({ id: record.node_id, name: record.name || record.node_id, sessions: 'Session telemetry unavailable', state: 'Enrolled' as const })),
      configurationEpoch: network.configuration_epoch,
      lastAction: `Configuration epoch ${network.configuration_epoch}`,
      updatedBy: 'Controller API',
      updatedAt: dateLabel(network.created_at_unix_seconds),
    }
  })
  const relays: InfrastructureRelay[] = (source?.relays ?? []).map((relay) => ({
    id: relay.relay_id,
    name: relay.name,
    endpoint: relay.endpoint,
    networkId: relay.network_id,
    sessions: 0,
    enabled: relay.enabled,
    reachable: false,
    certificateDays: 0,
    lastProbe: 'Probe time not exposed by controller',
    lastAction: `Configuration epoch ${relay.configuration_epoch}`,
    updatedBy: 'Controller API',
    updatedAt: dateLabel(relay.created_at_unix_seconds),
    createdAt: dateLabel(relay.created_at_unix_seconds),
    configurationEpoch: relay.configuration_epoch,
  }))

  return { ...control, networks, relays }
}
