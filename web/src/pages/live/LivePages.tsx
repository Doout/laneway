import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { NavLink, useNavigate, useParams } from 'react-router-dom'
import { ArrowRight, Ban, FileKey2, KeyRound, Link2, MonitorDot, Network, Plus, RadioTower, Route as RouteIcon, ShieldCheck, TriangleAlert, Users } from 'lucide-react'
import { ActionPanel, Button, Callout, DataTable, DetailLayout, EmptyState, EntityTitle, Field, FilterSelect, FormStack, IdentityBlock, PageHeader, RecordList, ResourceLink, SearchField, Section, Status, TokenBox, Toolbar, type DataColumn } from '../../components/ui'
import { controllerOrigin, useControlPlane, type ControllerACLRule, type ControllerAccessGrant, type ControllerAccessTeam, type ControllerAccessUser, type ControllerAuditEvent, type ControllerCertificate, type ControllerNetwork, type ControllerNode, type ControllerRoute, type IssuedEnrollmentToken } from '../../lib/control-plane'
import { isCanonicalIpPrefix } from '../../lib/ip-prefix'
import { durableNodeEnrollmentCommand, userEnrollmentCommand } from '../../lib/enrollment-commands'

function time(seconds?: number) {
  return seconds ? new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(seconds * 1000)) : 'Not recorded'
}

function timestampExpired(seconds?: number) {
  return seconds !== undefined && seconds <= Math.floor(Date.now() / 1000)
}

export function liveNodeState(node: ControllerNode) {
  const leaseExpired = node.enrollment_class === 'ephemeral' && timestampExpired(node.lease_expires_at_unix_seconds)
  if (leaseExpired) return { label: 'Lease expired', tone: 'muted' as const, inactive: true }
  if (node.revoked_at_unix_seconds !== undefined) return { label: 'Revoked', tone: 'danger' as const, inactive: true }
  return { label: 'Enrolled', tone: 'positive' as const, inactive: false }
}

export function liveRouteMode(mode: ControllerRoute['mode']) {
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

export function liveRouteState(route: ControllerRoute) {
  if ((route.state === 'advertised' || route.state === 'approved') && timestampExpired(route.valid_until_unix_seconds)) {
    return { label: 'Expired', tone: 'muted' as const, actionable: false }
  }
  if (route.state === 'advertised') return { label: 'Advertised', tone: 'warning' as const, actionable: true }
  if (route.state === 'approved') return { label: 'Approved', tone: 'positive' as const, actionable: true }
  if (route.state === 'withdrawn') return { label: 'Withdrawn', tone: 'muted' as const, actionable: false }
  return { label: 'Rejected', tone: 'danger' as const, actionable: false }
}

export function liveCertificateState(
  certificate: Pick<ControllerCertificate, 'not_before_unix_seconds' | 'not_after_unix_seconds' | 'revoked_at_unix_seconds'>,
  nowUnixSeconds = Math.floor(Date.now() / 1000),
) {
  if (certificate.revoked_at_unix_seconds !== undefined) return { label: 'Revoked', tone: 'danger' as const }
  if (nowUnixSeconds < certificate.not_before_unix_seconds) return { label: 'Not yet valid', tone: 'warning' as const }
  if (nowUnixSeconds >= certificate.not_after_unix_seconds) return { label: 'Expired', tone: 'muted' as const }
  return { label: 'Valid', tone: 'positive' as const }
}

export function liveACLRuleLabel(rule: ControllerACLRule) {
  return rule.description.trim() || `${rule.action === 'accept' ? 'Allow' : 'Deny'} rule ${rule.priority}`
}

function ErrorMessage({ value }: { value: string }) {
  return value ? <div role="alert"><Callout tone="danger">{value}</Callout></div> : null
}

function Missing({ title, back }: { title: string; back: string }) {
  return <EmptyState icon={<TriangleAlert />} title={title} description="The controller inventory does not contain this record." action={<Button to={back} variant="primary">Back</Button>} />
}

type RecordVisibility = 'current' | 'all'
const subnetRouterCapability = 1 << 3
const exitNodeCapability = 1 << 4
const emptyNodes: ControllerNode[] = []

type NetworkConnection = {
  connection_id: string
  source_network_id: string
  destination_network_id: string
  direction: 'one_way' | 'two_way'
  state: 'draft' | 'active' | 'disabled'
  default_action: 'deny'
  created_at_unix_seconds: number
}

type NetworkConnectionRule = {
  rule_id: string
  connection_id: string
  source_kind: 'team' | 'user' | 'node'
  source_id: string
  target_kind: 'network' | 'node'
  target_id?: string
  protocol: 'any' | 'tcp' | 'udp' | 'icmp'
  destination_ports?: string
}

function networkConnectionSourceId(kind: NetworkConnectionRule['source_kind'], choice: ControllerAccessTeam | ControllerAccessUser | ControllerNode) {
  return kind === 'team' ? (choice as ControllerAccessTeam).team_id : kind === 'user' ? (choice as ControllerAccessUser).user_id : (choice as ControllerNode).node_id
}

function VisibilityToolbar({ value, onChange, currentLabel, visible, total }: {
  value: RecordVisibility
  onChange: (value: RecordVisibility) => void
  currentLabel: string
  visible: number
  total: number
}) {
  return <Toolbar filters={<>
    <FilterSelect label="Record visibility" value={value} onChange={(next) => onChange(next as RecordVisibility)}>
      <option value="current">{currentLabel}</option>
      <option value="all">All records</option>
    </FilterSelect>
    <span className="inventory-result-count" aria-live="polite">{visible} of {total} shown</span>
  </>} />
}

export function LiveOverviewPage() {
  const { inventory, inventoryPending, inventoryError, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const rows = [
    ['Nodes', inventory?.nodes.filter((node) => !liveNodeState(node).inactive).length ?? 0, 'node.read', MonitorDot],
    ['Routes', inventory?.routes.filter((route) => liveRouteState(route).actionable).length ?? 0, 'route.read', RouteIcon],
    ['Access rules', inventory?.aclRules.filter((rule) => rule.enabled).length ?? 0, 'acl.read', ShieldCheck],
    ['Relays', inventory?.relays.filter((relay) => relay.enabled).length ?? 0, 'relay.read', RadioTower],
  ] as const
  return <>
    <PageHeader title="Overview" description={inventory?.network ? `${inventory.network.name} network inventory` : 'Select a network to view its inventory'} />
    <ErrorMessage value={inventoryError} />
    {inventoryPending ? <p role="status">Refreshing inventory…</p> : null}
    {inventory && inventory.networks.length > 1 && !inventory.network ? <Callout>Select a network.</Callout> : null}
    {inventory ? <section className="overview-metrics" aria-label="Network inventory summary">
      {rows.filter(([, , permission]) => Boolean(networkId && hasPermission(permission, networkId))).map(([label, count, , Icon]) => <div key={label} className="overview-metric"><span className="overview-metric__icon"><Icon aria-hidden="true" size={19} /></span><span className="overview-metric__label">{label}</span><strong>{count}</strong><span className="overview-metric__meta">in this network</span></div>)}
    </section> : null}
  </>
}

export function LiveNodesPage() {
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const records = inventory?.nodes ?? emptyNodes
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const [networkFilter, setNetworkFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [otherNodes, setOtherNodes] = useState<ControllerNode[]>([])
  const [otherRoutes, setOtherRoutes] = useState<ControllerRoute[]>([])
  const [movingNodeId, setMovingNodeId] = useState('')
  const [moveDestinationId, setMoveDestinationId] = useState('')
  const [movePending, setMovePending] = useState(false)
  const [moveError, setMoveError] = useState('')
  const [creatingNetwork, setCreatingNetwork] = useState(false)
  const [networkName, setNetworkName] = useState('')
  const [ipv4Pool, setIPv4Pool] = useState('')
  const [networkPending, setNetworkPending] = useState(false)
  const [networkError, setNetworkError] = useState('')
  const [creatingConnection, setCreatingConnection] = useState(false)
  const [destinationNetworkId, setDestinationNetworkId] = useState('')
  const [connectionDirection, setConnectionDirection] = useState<'one_way' | 'two_way'>('one_way')
  const [connectionPending, setConnectionPending] = useState(false)
  const [connectionError, setConnectionError] = useState('')
  const [connections, setConnections] = useState<NetworkConnection[]>([])
  const [configuringConnectionId, setConfiguringConnectionId] = useState('')
  const [connectionRules, setConnectionRules] = useState<NetworkConnectionRule[]>([])
  const [ruleSourceKind, setRuleSourceKind] = useState<NetworkConnectionRule['source_kind']>('team')
  const [ruleSourceId, setRuleSourceId] = useState('')
  const [ruleTargetKind, setRuleTargetKind] = useState<NetworkConnectionRule['target_kind']>('network')
  const [ruleTargetId, setRuleTargetId] = useState('')
  const [ruleProtocol, setRuleProtocol] = useState<NetworkConnectionRule['protocol']>('any')
  const [rulePorts, setRulePorts] = useState('')
  const [rulePending, setRulePending] = useState(false)
  const [ruleError, setRuleError] = useState('')
  const allNodes = useMemo(() => [...records, ...otherNodes].filter((node, index, nodes) => nodes.findIndex((candidate) => candidate.node_id === node.node_id) === index), [otherNodes, records])
  const allRoutes = useMemo(() => [...(inventory?.routes ?? []), ...otherRoutes].filter((route, index, routes) => routes.findIndex((candidate) => candidate.route_id === route.route_id) === index), [inventory?.routes, otherRoutes])
  const assignedRecords = networkFilter === 'all' ? allNodes : networkFilter === 'unassigned' ? [] : allNodes.filter((node) => node.network_id === networkFilter)
  const normalizedQuery = query.trim().toLowerCase()
  const visibleRecords = assignedRecords.filter((node) => (visibility === 'all' || !liveNodeState(node).inactive) && (!normalizedQuery || [node.name, node.node_id, node.ipv4_address, node.ipv6_address].some((value) => value?.toLowerCase().includes(normalizedQuery))))
  const activeRoutes = allRoutes.filter((route) => liveRouteState(route).actionable)
  const networkExits = activeRoutes.filter((route) => route.kind === 'exit' && route.state === 'approved')
  const otherNetworks = (inventory?.networks ?? []).filter((network) => network.network_id !== networkId)
  const configuringConnection = connections.find((connection) => connection.connection_id === configuringConnectionId)
  const connectionDestination = inventory?.networks.find((network) => network.network_id === configuringConnection?.destination_network_id)
  const sourceChoices = useMemo(() => ruleSourceKind === 'team' ? inventory?.accessTeams ?? [] : ruleSourceKind === 'user' ? inventory?.accessUsers ?? [] : records, [inventory?.accessTeams, inventory?.accessUsers, records, ruleSourceKind])
  const sourceChoiceName = (choice: ControllerAccessTeam | ControllerAccessUser | ControllerNode) => choice.name || networkConnectionSourceId(ruleSourceKind, choice)
  const movingNode = allNodes.find((node) => node.node_id === movingNodeId)
  const moveDestinations = (inventory?.networks ?? []).filter((network) => network.network_id !== movingNode?.network_id)
  useEffect(() => {
    let current = true
    const networks = inventory?.networks ?? []
    const requests = networks.filter((network) => network.network_id !== networkId && hasPermission('node.read', network.network_id)).map(async (network) => {
      const prefix = `/v1/admin/networks/${network.network_id}`
      const [nodes, routes] = await Promise.all([
        request<{ nodes: ControllerNode[] }>(`${prefix}/nodes?limit=1000`),
        hasPermission('route.read', network.network_id) ? request<{ routes: ControllerRoute[] }>(`${prefix}/routes?limit=1000`) : Promise.resolve({ routes: [] }),
      ])
      return { nodes: nodes.nodes, routes: routes.routes }
    })
    void Promise.all(requests).then((results) => {
      if (current) { setOtherNodes(results.flatMap((result) => result.nodes)); setOtherRoutes(results.flatMap((result) => result.routes)) }
    }).catch(() => { if (current) { setOtherNodes([]); setOtherRoutes([]) } })
    return () => { current = false }
  }, [hasPermission, inventory?.networks, networkId, request])
  useEffect(() => {
    let current = true
    if (!networkId) { setConnections([]); return () => { current = false } }
    void request<{ connections: NetworkConnection[] }>(`/v1/admin/network-connections?network_id=${networkId}`).then((result) => {
      if (current) setConnections(result.connections)
    }).catch(() => { if (current) setConnections([]) })
    return () => { current = false }
  }, [networkId, request])
  useEffect(() => {
    if (!otherNetworks.some((network) => network.network_id === destinationNetworkId)) setDestinationNetworkId(otherNetworks[0]?.network_id ?? '')
  }, [destinationNetworkId, otherNetworks])
  useEffect(() => {
    if (!sourceChoices.some((choice) => networkConnectionSourceId(ruleSourceKind, choice) === ruleSourceId)) setRuleSourceId(sourceChoices[0] ? networkConnectionSourceId(ruleSourceKind, sourceChoices[0]) : '')
  }, [ruleSourceId, ruleSourceKind, sourceChoices])
  useEffect(() => {
    if (!moveDestinations.some((network) => network.network_id === moveDestinationId)) setMoveDestinationId(moveDestinations[0]?.network_id ?? '')
  }, [moveDestinationId, moveDestinations])
  async function createNetwork(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const name = networkName.trim()
    const pool = ipv4Pool.trim()
    if (name.length < 2) return setNetworkError('Enter a Network name with at least two characters.')
    if (!isCanonicalIpPrefix(pool, { family: 'ipv4', minBits: 8, maxBits: 30 })) return setNetworkError('Use a canonical, routable IPv4 pool between /8 and /30.')
    if (inventory?.networks.some((network) => network.name.toLowerCase() === name.toLowerCase())) return setNetworkError('A Network with this name already exists.')
    setNetworkPending(true); setNetworkError('')
    try {
      await request<ControllerNetwork>('/v1/admin/networks', { method: 'POST', body: { name, ipv4_pool: pool } })
      await refresh()
      setCreatingNetwork(false); setNetworkName(''); setIPv4Pool('')
    } catch (cause) { setNetworkError(cause instanceof Error ? cause.message : 'Network creation failed.') }
    finally { setNetworkPending(false) }
  }
  async function createConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!networkId || !destinationNetworkId) return setConnectionError('Choose a destination Network.')
    setConnectionPending(true); setConnectionError('')
    try {
      const created = await request<NetworkConnection>('/v1/admin/network-connections', { method: 'POST', body: { source_network_id: networkId, destination_network_id: destinationNetworkId, direction: connectionDirection, default_action: 'deny' } })
      setConnections((current) => [...current.filter((connection) => connection.connection_id !== created.connection_id), created])
      setCreatingConnection(false)
    } catch (cause) { setConnectionError(cause instanceof Error ? cause.message : 'Connection creation failed.') }
    finally { setConnectionPending(false) }
  }
  async function createConnectionRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!configuringConnection || !ruleSourceId || (ruleTargetKind === 'node' && !ruleTargetId)) return setRuleError('Choose a source and destination for this rule.')
    if ((ruleProtocol === 'tcp' || ruleProtocol === 'udp') && rulePorts.trim() && !/^\d+(?:-\d+)?(?:,\s*\d+(?:-\d+)?)*$/.test(rulePorts.trim())) return setRuleError('Use ports such as 443 or 80,443,8000-8100.')
    setRulePending(true); setRuleError('')
    try {
      const created = await request<NetworkConnectionRule>(`/v1/admin/network-connections/${configuringConnection.connection_id}/rules`, { method: 'POST', body: { source_kind: ruleSourceKind, source_id: ruleSourceId, target_kind: ruleTargetKind, ...(ruleTargetKind === 'node' ? { target_id: ruleTargetId } : {}), protocol: ruleProtocol, ...((ruleProtocol === 'tcp' || ruleProtocol === 'udp') && rulePorts.trim() ? { destination_ports: rulePorts.trim() } : {}) } })
      setConnectionRules((current) => [...current, created]); setRulePorts('')
    } catch (cause) { setRuleError(cause instanceof Error ? cause.message : 'Connection rule creation failed.') }
    finally { setRulePending(false) }
  }
  async function moveNode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!movingNode || !moveDestinationId) return setMoveError('Choose a destination Network.')
    if (networkExits.some((route) => route.node_id === movingNode.node_id)) return setMoveError('Remove the approved Network Exit route before moving this Node.')
    setMovePending(true); setMoveError('')
    try {
      await request(`/v1/admin/nodes/${movingNode.node_id}/move`, { method: 'POST', body: { destination_network_id: moveDestinationId } })
      setMovingNodeId(''); await refresh()
    } catch (cause) { setMoveError(cause instanceof Error ? cause.message : 'Node move failed.') }
    finally { setMovePending(false) }
  }
  function routingRole(node: ControllerNode) {
    if (networkExits.some((route) => route.node_id === node.node_id)) return <Status tone="positive">Network exit</Status>
    if (node.enabled_capabilities & exitNodeCapability) return <Status tone="warning">Exit eligible</Status>
    if (activeRoutes.some((route) => route.node_id === node.node_id && route.kind === 'subnet') || node.enabled_capabilities & subnetRouterCapability) return 'Subnet router'
    return 'Standard node'
  }
  return <div className="network-workspace-page">
    <PageHeader title="Networks" description="Nodes, address space, and routing stay inside an explicit Network boundary" action={hasPermission('network.create') ? <Button variant="primary" onClick={() => { setCreatingNetwork((value) => !value); setNetworkError('') }}><Plus size={16} />Add Network</Button> : undefined} />
    {creatingNetwork ? <form className="network-create" onSubmit={createNetwork}>
      <header><div><span>New isolated boundary</span><h2>Create Network</h2><p>A new Network starts with no nodes, routes, exits, or connections.</p></div></header>
      <div className="network-create__fields"><Field label="Network name"><input autoFocus maxLength={253} placeholder="Development" value={networkName} onChange={(event) => setNetworkName(event.target.value)} /></Field><Field label="IPv4 address pool" hint="Must not overlap an existing Network."><input placeholder="100.97.0.0/16" value={ipv4Pool} onChange={(event) => setIPv4Pool(event.target.value)} /></Field></div>
      <ErrorMessage value={networkError} /><footer className="button-row"><Button type="submit" variant="primary" disabled={networkPending}>{networkPending ? 'Creating…' : 'Create isolated Network'}</Button><Button type="button" variant="quiet" disabled={networkPending} onClick={() => setCreatingNetwork(false)}>Cancel</Button></footer>
    </form> : null}
    {inventory?.network ? <>
      <section className="network-groups" aria-labelledby="network-groups-title"><header><h2 id="network-groups-title">{inventory.networks.length} {inventory.networks.length === 1 ? 'Network' : 'Networks'}</h2><p>Node and policy groups in this workspace—not separate tenants.</p></header><div className="network-group-list">{inventory.networks.map((network) => { const nodes = allNodes.filter((node) => node.network_id === network.network_id); const exits = networkExits.filter((route) => route.network_id === network.network_id); return <article key={network.network_id}><span className="network-group-list__icon"><Network aria-hidden="true" size={18} /></span><div><strong>{network.name}</strong><code>{network.ipv4_pool}</code></div><div className="network-group-list__stats"><span><strong>{nodes.length}</strong> Nodes</span><span><strong>{exits.length}</strong> {exits.length === 1 ? 'Exit' : 'Exits'}</span></div></article> })}</div></section>
      <section className="network-nodes" aria-labelledby="network-nodes-title">
        <header className="network-nodes__header"><div><h2 id="network-nodes-title">Nodes</h2><p>Move regular Nodes between Networks. Exit Nodes stay locked until their Exit route is removed.</p></div>{networkId && hasPermission('enrollment.issue', networkId) ? <Button to="/nodes/new" variant="primary"><Plus size={16} />Add node</Button> : null}</header>
        <Toolbar filters={<><FilterSelect label="Network" value={networkFilter} onChange={setNetworkFilter}><option value="all">All Networks</option>{inventory.networks.map((network) => <option key={network.network_id} value={network.network_id}>{network.name}</option>)}<option value="unassigned">Unassigned</option></FilterSelect><FilterSelect label="Record visibility" value={visibility} onChange={(value) => setVisibility(value as RecordVisibility)}><option value="current">Active only</option><option value="all">All records</option></FilterSelect><span className="inventory-result-count" aria-live="polite">{visibleRecords.length} of {assignedRecords.length} shown</span></>}><SearchField label="Search nodes" placeholder="Search name, address, or node ID" value={query} onChange={setQuery} /></Toolbar>
        {visibleRecords.length ? <div className="node-list" role="list" aria-label="Nodes">{visibleRecords.map((node) => { const state = liveNodeState(node); const exitLocked = networkExits.some((route) => route.node_id === node.node_id); return <article className="node-list__row" role="listitem" key={node.node_id}>
          <EntityTitle icon={<MonitorDot size={16} />} subtitle={node.node_id}>{node.name || node.node_id}</EntityTitle>
          <div className="node-list__placement"><span>Placement</span><strong>{inventory.networks.find((network) => network.network_id === node.network_id)?.name ?? 'Unassigned'}</strong><code>{[node.ipv4_address, node.ipv6_address].filter(Boolean).join(' · ') || 'No address'}</code></div>
          <div className="node-list__posture"><span>Role &amp; state</span><div>{routingRole(node)}<Status tone={state.tone}>{state.label}</Status></div><small>{node.enrollment_class} enrollment</small></div>
          <div className="node-list__action">{exitLocked ? <span className="node-move-locked">Exit locked</span> : <Button variant="quiet" onClick={() => { setMovingNodeId(node.node_id); setMoveError('') }}>Move</Button>}</div>
        </article> })}</div> : <div className="data-empty">{networkFilter === 'unassigned' ? <><MonitorDot aria-hidden="true" /><h2>No unassigned nodes</h2><p>Unassigned Nodes cannot connect or advertise routes. Move an eligible Node into any Network from this list.</p></> : <p>No nodes match the current filters.</p>}</div>}
        {movingNode ? <form className="node-move" onSubmit={moveNode}><header><div><span>Move Node</span><h3>{movingNode.name || movingNode.node_id}</h3><p>The Node keeps its ownership, but receives new overlay addresses and must reconnect with identity for the destination Network.</p></div></header><div className="node-move__path"><strong>{inventory.networks.find((network) => network.network_id === movingNode.network_id)?.name ?? 'Unassigned'}</strong><ArrowRight aria-hidden="true" size={18} /><Field label="Destination Network"><select value={moveDestinationId} onChange={(event) => setMoveDestinationId(event.target.value)}>{moveDestinations.map((network) => <option key={network.network_id} value={network.network_id}>{network.name}</option>)}</select></Field></div><Callout tone="warning">Existing non-Exit routes are withdrawn during the move. Access is recalculated from destination Network policy.</Callout><ErrorMessage value={moveError} /><div className="button-row"><Button type="submit" variant="primary" disabled={movePending || !moveDestinationId}>{movePending ? 'Moving…' : 'Move Node'}</Button><Button type="button" variant="quiet" disabled={movePending} onClick={() => setMovingNodeId('')}>Cancel</Button></div></form> : null}
      </section>
      <section className="network-connections" aria-labelledby="network-connections-title">
        <header className="network-connections__header"><div><span>Explicit boundaries</span><h2 id="network-connections-title">Connected Networks</h2><p>Define possible reachability; traffic stays denied until routing and allow rules are configured.</p></div>{otherNetworks.length ? <Button onClick={() => { setCreatingConnection((value) => !value); setConnectionError('') }}><Link2 size={16} />Connect Network</Button> : null}</header>
        {creatingConnection ? <form className="network-connection-form" onSubmit={createConnection}>
          <div className="network-connection-form__path"><strong>{inventory.network.name}</strong><ArrowRight aria-hidden="true" size={18} /><Field label="Destination Network"><select value={destinationNetworkId} onChange={(event) => setDestinationNetworkId(event.target.value)}>{otherNetworks.map((network) => <option key={network.network_id} value={network.network_id}>{network.name}</option>)}</select></Field></div>
          <div className="network-connection-form__controls"><Field label="Direction"><select value={connectionDirection} onChange={(event) => setConnectionDirection(event.target.value as typeof connectionDirection)}><option value="one_way">One way</option><option value="two_way">Both directions</option></select></Field><Field label="Initial access"><input readOnly value="Deny all traffic" /></Field><Field label="Route exposure"><input readOnly value="None until gateways are configured" /></Field></div>
          <Callout tone="warning">Creating this draft does not route traffic. Gateway selection and explicit allow rules are required before activation.</Callout><ErrorMessage value={connectionError} /><div className="button-row"><Button type="submit" variant="primary" disabled={connectionPending || !destinationNetworkId}>{connectionPending ? 'Creating…' : 'Create draft connection'}</Button><Button type="button" variant="quiet" disabled={connectionPending} onClick={() => setCreatingConnection(false)}>Cancel</Button></div>
        </form> : null}
        {connections.length ? <div className="network-connection-list">{connections.map((connection) => { const source = inventory.networks.find((network) => network.network_id === connection.source_network_id); const destination = inventory.networks.find((network) => network.network_id === connection.destination_network_id); return <article key={connection.connection_id} className="network-connection"><span className="network-connection__icon"><Link2 aria-hidden="true" size={18} /></span><div><strong>{source?.name ?? 'Unknown Network'} <ArrowRight aria-hidden="true" size={14} /> {destination?.name ?? 'Unknown Network'}</strong><p>{connection.direction === 'two_way' ? 'Both directions' : 'One way'} · Default deny · No transitive access</p></div><Status tone={connection.state === 'active' ? 'positive' : 'warning'}>{connection.state === 'active' ? 'Active' : 'Routing inactive'}</Status><Button variant="quiet" onClick={() => { setConfiguringConnectionId((current) => current === connection.connection_id ? '' : connection.connection_id); setRuleError('') }}>Configure policy</Button></article> })}</div> : <div className="network-connections__empty"><Link2 aria-hidden="true" size={20} /><div><strong>No connected Networks</strong><p>{otherNetworks.length ? 'Create a draft connection to define direction, routing, and access.' : 'Add another Network before defining cross-Network access.'}</p></div></div>}
        {configuringConnection ? <form className="network-policy-editor" onSubmit={createConnectionRule}>
          <header><div><span>Default deny</span><h3>Connection policy</h3><p>Add only the traffic that should cross from {inventory.network.name} to {connectionDestination?.name ?? 'the destination Network'}.</p></div><Status tone="warning">0 implicit grants</Status></header>
          <div className="network-policy-editor__fields"><Field label="Source type"><select value={ruleSourceKind} onChange={(event) => setRuleSourceKind(event.target.value as typeof ruleSourceKind)}><option value="team">Team</option><option value="user">User</option><option value="node">Node</option></select></Field><Field label={ruleSourceKind === 'team' ? 'Source Team' : ruleSourceKind === 'user' ? 'Source User' : 'Source Node'}><select value={ruleSourceId} onChange={(event) => setRuleSourceId(event.target.value)}><option value="">Choose source</option>{sourceChoices.map((choice) => <option key={networkConnectionSourceId(ruleSourceKind, choice)} value={networkConnectionSourceId(ruleSourceKind, choice)}>{sourceChoiceName(choice)}</option>)}</select></Field><Field label="Destination scope"><select value={ruleTargetKind} onChange={(event) => { setRuleTargetKind(event.target.value as typeof ruleTargetKind); setRuleTargetId('') }}><option value="network">Entire destination Network</option><option value="node">One destination Node</option></select></Field>{ruleTargetKind === 'node' ? <Field label="Destination Node" hint="Add and enroll destination Nodes before granting access."><select value={ruleTargetId} onChange={(event) => setRuleTargetId(event.target.value)}><option value="">No destination Nodes available</option></select></Field> : null}<Field label="Protocol"><select value={ruleProtocol} onChange={(event) => { setRuleProtocol(event.target.value as typeof ruleProtocol); if (event.target.value !== 'tcp' && event.target.value !== 'udp') setRulePorts('') }}><option value="any">Any protocol</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></Field>{ruleProtocol === 'tcp' || ruleProtocol === 'udp' ? <Field label="Destination ports" hint="Comma-separated ports or ranges."><input placeholder="443,8000-8100" value={rulePorts} onChange={(event) => setRulePorts(event.target.value)} /></Field> : null}</div>
          {ruleTargetKind === 'network' ? <Callout tone="warning">This target includes every Node in {connectionDestination?.name ?? 'the destination Network'}. Choose one destination Node for tighter access.</Callout> : null}<ErrorMessage value={ruleError} /><div className="button-row"><Button type="submit" variant="primary" disabled={rulePending || !ruleSourceId || (ruleTargetKind === 'node' && !ruleTargetId)}>{rulePending ? 'Adding…' : 'Add allow rule'}</Button><Button type="button" variant="quiet" onClick={() => setConfiguringConnectionId('')}>Done</Button></div>
          {connectionRules.filter((rule) => rule.connection_id === configuringConnection.connection_id).length ? <div className="network-policy-rules">{connectionRules.filter((rule) => rule.connection_id === configuringConnection.connection_id).map((rule) => <div key={rule.rule_id}><Status tone="positive">Allow</Status><span>{rule.source_kind} → {rule.target_kind}</span><code>{rule.protocol.toUpperCase()}{rule.destination_ports ? ` · ${rule.destination_ports}` : ''}</code></div>)}</div> : <p className="network-policy-editor__empty">No allow rules. All cross-Network traffic is denied.</p>}
          <footer><strong>Activation checklist</strong><span>Gateway pair</span><Status tone="muted">Required</Status><span>Route review</span><Status tone="muted">Required</Status><span>Allow rules</span><Status tone={connectionRules.some((rule) => rule.connection_id === configuringConnection.connection_id) ? 'positive' : 'muted'}>{connectionRules.some((rule) => rule.connection_id === configuringConnection.connection_id) ? 'Ready' : 'Required'}</Status></footer>
        </form> : null}
      </section>
    </> : <EmptyState icon={<Network />} title="No Networks" description="Create a Network to begin organizing Nodes and policy." />}
  </div>
}

export function LiveNodeDetailPage() {
  const { nodeId } = useParams()
  const { inventory, hasPermission } = useControlPlane()
  const node = inventory?.nodes.find((candidate) => candidate.node_id === nodeId)
  if (!node) return <Missing title="Node not found" back="/networks" />
  const state = liveNodeState(node)
  const canManage = hasPermission('node.manage', node.network_id) && !state.inactive
  const exitRoute = inventory?.routes.find((route) => route.node_id === node.node_id && route.kind === 'exit' && route.state === 'approved' && liveRouteState(route).actionable)
  const subnetRoutes = (inventory?.routes ?? []).filter((route) => route.node_id === node.node_id && route.kind === 'subnet' && liveRouteState(route).actionable)
  const routingRole = exitRoute ? 'Network exit' : node.enabled_capabilities & exitNodeCapability ? 'Eligible for Network Exit' : subnetRoutes.length || node.enabled_capabilities & subnetRouterCapability ? 'Subnet router' : 'Standard node'
  return <>
    <PageHeader title={node.name || 'Node'} description={`Node in ${inventory?.network?.name ?? 'the selected Network'}`} action={<Button to="/networks" variant="quiet">Back to Network</Button>} />
    <DetailLayout identity={<IdentityBlock icon={<MonitorDot size={30} />} title={node.name || node.node_id} state={<Status tone={state.tone}>{state.label}</Status>} actions={canManage ? <><Button to={`/nodes/${node.node_id}/capabilities`}>Capabilities</Button><Button to={`/nodes/${node.node_id}/revoke`} variant="danger">Revoke</Button></> : undefined} metadata={[["Node ID", <code>{node.node_id}</code>], ["Network ID", <code>{node.network_id}</code>], ["Created", time(node.created_at_unix_seconds)]]} />}>
      <Section title="Overlay addresses"><RecordList rows={[["IPv4", <code>{node.ipv4_address ?? 'Not assigned'}</code>], ["IPv6", <code>{node.ipv6_address ?? 'Not assigned'}</code>]]} /></Section>
      <Section title="Network membership"><RecordList rows={[["Network", inventory?.network?.name ?? node.network_id], ["Routing role", routingRole], ["Network Exit route", exitRoute ? <code>{exitRoute.prefix}</code> : 'Not assigned'], ["Subnet routes", subnetRoutes.length]]} /></Section>
    </DetailLayout>
  </>
}

function EnrollmentForm({ userId }: { userId?: string }) {
  const { inventory, request, captureSessionBinding, storeIssuedEnrollmentToken } = useControlPlane()
  const navigate = useNavigate()
  const user = userId ? inventory?.accessUsers.find((candidate) => candidate.user_id === userId) : undefined
  const isUserEnrollment = Boolean(userId)
  const [name, setName] = useState('')
  const [kind, setKind] = useState(isUserEnrollment ? 'ephemeral' : 'durable')
  const [hours, setHours] = useState('8')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const network = inventory?.network
    const cleanName = name.trim()
    if (!network || cleanName.length < 2 || (isUserEnrollment && !user)) return setError('Enter a name and choose an available User and Network.')
    const sessionBinding = captureSessionBinding()
    if (!sessionBinding) return setError('The administrator session changed. Try again.')
    setPending(true); setError('')
    try {
      const result = await request<{ enrollment_token: string }>('/v1/admin/enrollment-tokens', { method: 'POST', body: {
        network_id: network.network_id,
        ...(user ? { user_id: user.user_id } : {}),
        label: cleanName,
        requested_name: cleanName,
        expires_at_unix_seconds: Math.floor(Date.now() / 1000) + (isUserEnrollment ? 900 : 86_400),
        enrollment_class: kind,
        ...(isUserEnrollment ? { session_lifetime_seconds: kind === 'ephemeral' ? Number(hours) * 3600 : 0 } : { enabled_capabilities: 0 }),
      } })
      const host = new URL(controllerOrigin()).host
      if (typeof result.enrollment_token !== 'string' || result.enrollment_token.length === 0) throw new Error('The controller returned an invalid enrollment token.')
      const issued: IssuedEnrollmentToken = {
        kind: 'command',
        token: result.enrollment_token,
        heading: isUserEnrollment ? `${user?.name ?? 'User'} node token issued` : 'Node token issued',
        command: isUserEnrollment
          ? userEnrollmentCommand(host, kind === 'ephemeral' ? 'Ephemeral' : 'Remembered')
          : durableNodeEnrollmentCommand(host),
      }
      if (!storeIssuedEnrollmentToken(sessionBinding, issued)) throw new Error('The administrator session changed before the token could be shown.')
      navigate(isUserEnrollment ? `/users/${userId}/enroll/token` : '/nodes/new/token')
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Token issuance failed.') } finally { setPending(false) }
  }
  return <>
    <PageHeader title={isUserEnrollment ? `Enroll a node for ${user?.name ?? 'User'}` : 'Add node'} description={isUserEnrollment ? 'Create a single-use enrollment command bound to this User' : 'Create a single-use enrollment command for a durable node'} />
    <FormStack onSubmit={submit}>
      <Field label={isUserEnrollment ? 'Device name' : 'Node name'}><input value={name} onChange={(event) => setName(event.target.value)} autoComplete="off" /></Field>
      {isUserEnrollment ? <><Field label="Enrollment"><select value={kind} onChange={(event) => setKind(event.target.value)}><option value="ephemeral">Ephemeral</option><option value="remembered">Remembered</option></select></Field><Field label="Lease duration (hours)"><input type="number" min="1" max="24" disabled={kind !== 'ephemeral'} value={hours} onChange={(event) => setHours(event.target.value)} /></Field></> : null}
      <Field label="Network"><input readOnly value={inventory?.network?.name ?? 'No network'} /></Field>
      <ErrorMessage value={error} />
      <div className="button-row"><Button type="submit" variant="primary" disabled={pending || !inventory?.network || (isUserEnrollment && !user)}><KeyRound size={16} />{pending ? 'Issuing…' : 'Issue token'}</Button><Button to={isUserEnrollment ? `/users/${userId}` : '/networks'} variant="quiet">Cancel</Button></div>
    </FormStack>
  </>
}

export function LiveAddNodePage() { return <EnrollmentForm /> }
export function LiveIssueUserPage() { return <LiveCreateUserPage /> }
export function LiveUserEnrollmentPage() { const { userId } = useParams(); return <EnrollmentForm userId={userId} /> }

export function LiveTokenPage({ user = false, userId }: { user?: boolean; userId?: string }) {
  const { peekIssuedEnrollmentToken, clearIssuedEnrollmentToken, isSessionBindingCurrent } = useControlPlane()
  const [issued] = useState(() => peekIssuedEnrollmentToken())
  useEffect(() => {
    if (issued) clearIssuedEnrollmentToken(issued.binding)
  }, [clearIssuedEnrollmentToken, issued])
  if (!issued || !isSessionBindingCurrent(issued.binding) || issued.value.kind !== 'command') return <Missing title="Token unavailable" back={userId ? `/users/${userId}/enroll` : user ? '/users/new' : '/nodes/new'} />
  const token = issued.value
  return <>
    <PageHeader title={token.heading} />
    <Callout tone="warning">Copy this single-use token now.</Callout>
    <TokenBox label="Enrollment token" value={token.token} />
    <Section title="Command"><pre><code>{token.command}</code></pre></Section>
    <Button to={user ? '/users' : '/networks'} variant="primary">Done</Button>
  </>
}

export function LiveNodeCapabilitiesPage() {
  const { nodeId } = useParams()
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const node = inventory?.nodes.find((candidate) => candidate.node_id === nodeId)
  const [mask, setMask] = useState(node?.enabled_capabilities ?? 0)
  const [error, setError] = useState('')
  useEffect(() => { if (node) setMask(node.enabled_capabilities) }, [node])
  if (!node) return <Missing title="Node not found" back="/networks" />
  if (liveNodeState(node).inactive) return <PageHeader title={liveNodeState(node).label} action={<Button to={`/nodes/${node.node_id}`}>View node</Button>} />
  const activeNode = node
  async function save() {
    try { await request(`/v1/admin/nodes/${activeNode.node_id}/capabilities`, { method: 'PUT', body: { enabled_capabilities: mask } }); await refresh(); navigate(`/nodes/${activeNode.node_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Update failed.') }
  }
  function setCapability(bit: number, enabled: boolean) { setMask((current) => enabled ? current | bit : current & ~bit) }
  return <><PageHeader title="Routing capabilities" description={`${node.name || node.node_id} in ${inventory?.network?.name ?? 'the selected Network'}`} /><ActionPanel><div className="capability-options"><label className="capability-option"><input type="checkbox" checked={Boolean(mask & subnetRouterCapability)} onChange={(event) => setCapability(subnetRouterCapability, event.target.checked)} /><span><strong>Publish subnet routes</strong><small>Allow this node to advertise private destinations inside this Network.</small></span></label><label className="capability-option"><input type="checkbox" checked={Boolean(mask & exitNodeCapability)} onChange={(event) => setCapability(exitNodeCapability, event.target.checked)} /><span><strong>Eligible for Network Exit</strong><small>This only makes the node eligible. It does not become an Exit until a default route is explicitly assigned and approved.</small></span></label></div><Callout tone="warning">A node must belong to this Network before it can receive either routing capability.</Callout><ErrorMessage value={error} /><div className="button-row"><Button variant="primary" onClick={() => void save()}>Save capabilities</Button><Button to={`/nodes/${node.node_id}`} variant="quiet">Cancel</Button></div></ActionPanel></>
}

export function LiveNodeRevokePage() {
  const { nodeId } = useParams()
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const node = inventory?.nodes.find((candidate) => candidate.node_id === nodeId)
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  if (!node) return <Missing title="Node not found" back="/networks" />
  if (liveNodeState(node).inactive) return <PageHeader title={liveNodeState(node).label} action={<Button to={`/nodes/${node.node_id}`}>View node</Button>} />
  const activeNode = node
  async function revoke() {
    try { await request(`/v1/admin/nodes/${activeNode.node_id}/revoke`, { method: 'POST', body: { reason: 'Revoked by administrator' } }); await refresh(); navigate(`/nodes/${activeNode.node_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Revocation failed.') }
  }
  return <><PageHeader title={`Revoke ${node.name || node.node_id}`} description="Disconnect this identity and prevent it from reconnecting" /><ActionPanel><Callout tone="danger">This action is permanent.</Callout><Field label={`Type ${node.name || node.node_id} to confirm`}><input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></Field><ErrorMessage value={error} /><Button variant="danger" disabled={confirmation !== (node.name || node.node_id)} onClick={() => void revoke()}>Revoke node</Button></ActionPanel></>
}

function PeopleTabs() {
  const { inventory } = useControlPlane()
  return <nav className="people-tabs" aria-label="People views">
    <NavLink to="/users" end><span>Users</span><span aria-hidden="true">{inventory?.accessUsers.length ?? 0}</span></NavLink>
    <NavLink to="/teams" end><span>Teams</span><span aria-hidden="true">{inventory?.accessTeams.length ?? 0}</span></NavLink>
  </nav>
}

export function LiveUsersPage() {
  const { inventory, hasPermission } = useControlPlane()
  const records = inventory?.accessUsers ?? []
  const networkId = inventory?.network?.network_id
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const visibleRecords = visibility === 'all' ? records : records.filter((user) => user.enabled)
  const columns: DataColumn<ControllerAccessUser>[] = [
    { key: 'user', label: 'User', render: (user) => <EntityTitle icon={<Users size={16} />} subtitle={user.user_id}>{user.name}</EntityTitle> },
    { key: 'devices', label: 'Nodes', render: (user) => (inventory?.nodes ?? []).filter((node) => node.user_id === user.user_id && !liveNodeState(node).inactive).length },
    { key: 'teams', label: 'Teams', render: (user) => (inventory?.accessMemberships ?? []).filter((member) => member.user_id === user.user_id).length },
    { key: 'state', label: 'State', render: (user) => <Status tone={user.enabled ? 'positive' : 'muted'}>{user.enabled ? 'Enabled' : 'Disabled'}</Status> },
    { key: 'open', label: '', render: (user) => <Button to={`/users/${user.user_id}`} variant="quiet">View</Button> },
  ]
  return <><PageHeader title="People" description="Manage Users, Teams, and their access in this Network" action={networkId && hasPermission('acl.manage', networkId) ? <Button to="/users/new" variant="primary"><Plus size={16} />Create user</Button> : undefined} /><PeopleTabs /><VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Enabled only" visible={visibleRecords.length} total={records.length} /><DataTable columns={columns} rows={visibleRecords} rowKey={(user) => user.user_id} empty={<p>No enabled Users. Choose All records to view disabled Users.</p>} /></>
}

export function LiveUserDetailPage() {
  const { userId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const user = inventory?.accessUsers.find((candidate) => candidate.user_id === userId)
  const [error, setError] = useState('')
  if (!user) return <Missing title="User not found" back="/users" />
  const activeUser = user
  const nodes = (inventory?.nodes ?? []).filter((node) => node.user_id === user.user_id)
  const teamIds = new Set((inventory?.accessMemberships ?? []).filter((member) => member.user_id === user.user_id).map((member) => member.team_id))
  const teams = (inventory?.accessTeams ?? []).filter((team) => teamIds.has(team.team_id))
  const grants = (inventory?.accessGrants ?? []).filter((grant) => grant.subject_kind === 'user' && grant.subject_id === user.user_id)
  const canManage = hasPermission('acl.manage', user.network_id)
  async function toggleUser() {
    try { await request(`/v1/admin/users/${activeUser.user_id}`, { method: 'PATCH', body: { enabled: !activeUser.enabled } }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'User update failed.') }
  }
  async function removeGrant(grantId: string) {
    try { await request(`/v1/admin/access-grants/${grantId}`, { method: 'DELETE' }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Grant removal failed.') }
  }
  return <><PageHeader title={user.name} description="Network User" action={<div className="button-row"><Button to="/users">All users</Button>{canManage ? <Button to={`/users/${user.user_id}/grants/new`}>Grant access</Button> : null}{user.enabled && hasPermission('enrollment.issue', user.network_id) ? <Button to={`/users/${user.user_id}/enroll`} variant="primary">Enroll node</Button> : null}</div>} /><ErrorMessage value={error} /><DetailLayout identity={<IdentityBlock icon={<Users size={30} />} title={user.name} state={<Status tone={user.enabled ? 'positive' : 'muted'}>{user.enabled ? 'Enabled' : 'Disabled'}</Status>} actions={canManage ? <Button variant={user.enabled ? 'danger' : 'primary'} onClick={() => void toggleUser()}>{user.enabled ? 'Disable user' : 'Enable user'}</Button> : undefined} metadata={[["User ID", <code>{user.user_id}</code>], ["Network ID", <code>{user.network_id}</code>], ["Created", time(user.created_at_unix_seconds)]]} />}>
    <Section title="Teams" meta={`${teams.length} assigned`}>{teams.length ? <div className="resource-list">{teams.map((team) => <ResourceLink key={team.team_id} to={`/teams/${team.team_id}`} icon={<Users size={18} />} title={team.name} />)}</div> : <div className="inline-empty">Not assigned to a Team.</div>}</Section>
    <Section title="Access grants" meta={`${grants.length} direct`}>{grants.length ? <div className="resource-list">{grants.map((grant) => <AccessGrantRow key={grant.grant_id} grant={grant} inventory={inventory} remove={canManage ? removeGrant : undefined} />)}</div> : <div className="inline-empty">No direct grants. Team grants may still apply.</div>}</Section>
    <Section title="Enrolled nodes" meta={`${nodes.length} total`}>{nodes.length ? <div className="resource-list">{nodes.map((node) => <ResourceLink key={node.node_id} to={`/nodes/${node.node_id}`} icon={<MonitorDot size={18} />} title={node.name || node.node_id} meta={node.enrollment_class} state={<Status tone={liveNodeState(node).tone}>{liveNodeState(node).label}</Status>} />)}</div> : <div className="inline-empty">No nodes enrolled for this User.</div>}</Section>
  </DetailLayout></>
}

function AccessGrantRow({ grant, inventory, remove }: { grant: ControllerAccessGrant; inventory: ReturnType<typeof useControlPlane>['inventory']; remove?: (id: string) => Promise<void> }) {
  const node = grant.node_id ? inventory?.nodes.find((candidate) => candidate.node_id === grant.node_id) : undefined
  const title = grant.target_kind === 'network' ? `Network: ${inventory?.network?.name ?? grant.network_id}` : grant.target_kind === 'exit' ? `Exit: ${node?.name ?? grant.node_id}` : `Node: ${node?.name ?? grant.node_id}`
  return <div className="access-grant-row"><span><strong>{title}</strong><small>{grant.target_kind === 'network' ? 'Exit access is not included' : grant.target_kind === 'exit' ? 'Default route only' : 'This node only'}</small></span>{remove ? <Button variant="danger" onClick={() => void remove(grant.grant_id)}>Remove</Button> : null}</div>
}

export function LiveCreateUserPage() { return <CreateAccessSubject kind="user" /> }
export function LiveCreateTeamPage() { return <CreateAccessSubject kind="team" /> }

function CreateAccessSubject({ kind }: { kind: 'user' | 'team' }) {
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!inventory?.network) return
    try {
      const created = await request<ControllerAccessUser | ControllerAccessTeam>(`/v1/admin/networks/${inventory.network.network_id}/${kind === 'user' ? 'users' : 'teams'}`, { method: 'POST', body: { name: name.trim() } })
      await refresh()
      navigate(kind === 'user' ? `/users/${(created as ControllerAccessUser).user_id}` : `/teams/${(created as ControllerAccessTeam).team_id}`)
    } catch (cause) { setError(cause instanceof Error ? cause.message : `${kind === 'user' ? 'User' : 'Team'} creation failed.`) }
  }
  return <><PageHeader title={`Create ${kind}`} description={kind === 'user' ? 'Add a person to this Network' : 'Group Users for shared access'} /><FormStack onSubmit={submit}><Field label="Name"><input autoFocus value={name} onChange={(event) => setName(event.target.value)} /></Field><ErrorMessage value={error} /><div className="button-row"><Button type="submit" variant="primary">Create {kind}</Button><Button to={kind === 'user' ? '/users' : '/teams'}>Cancel</Button></div></FormStack></>
}

export function LiveTeamsPage() {
  const { inventory, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const records = inventory?.accessTeams ?? []
  const columns: DataColumn<ControllerAccessTeam>[] = [
    { key: 'team', label: 'Team', render: (team) => <EntityTitle icon={<Users size={16} />} subtitle={team.team_id}>{team.name}</EntityTitle> },
    { key: 'members', label: 'Members', render: (team) => (inventory?.accessMemberships ?? []).filter((member) => member.team_id === team.team_id).length },
    { key: 'grants', label: 'Access grants', render: (team) => (inventory?.accessGrants ?? []).filter((grant) => grant.subject_kind === 'team' && grant.subject_id === team.team_id).length },
    { key: 'open', label: '', render: (team) => <Button to={`/teams/${team.team_id}`} variant="quiet">View</Button> },
  ]
  return <><PageHeader title="People" description="Manage Users, Teams, and their access in this Network" action={networkId && hasPermission('acl.manage', networkId) ? <Button to="/teams/new" variant="primary"><Plus size={16} />Create Team</Button> : undefined} /><PeopleTabs /><DataTable columns={columns} rows={records} rowKey={(team) => team.team_id} empty={<p>No Teams in this Network.</p>} /></>
}

export function LiveTeamDetailPage() {
  const { teamId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const team = inventory?.accessTeams.find((candidate) => candidate.team_id === teamId)
  const [selectedUser, setSelectedUser] = useState('')
  const [error, setError] = useState('')
  if (!team) return <Missing title="Team not found" back="/teams" />
  const activeTeam = team
  const memberships = (inventory?.accessMemberships ?? []).filter((member) => member.team_id === team.team_id)
  const memberIds = new Set(memberships.map((member) => member.user_id))
  const members = (inventory?.accessUsers ?? []).filter((user) => memberIds.has(user.user_id))
  const available = (inventory?.accessUsers ?? []).filter((user) => user.enabled && !memberIds.has(user.user_id))
  const grants = (inventory?.accessGrants ?? []).filter((grant) => grant.subject_kind === 'team' && grant.subject_id === team.team_id)
  const canManage = hasPermission('acl.manage', team.network_id)
  async function changeMember(userId: string, present: boolean) {
    try { await request(`/v1/admin/teams/${activeTeam.team_id}/members/${userId}`, { method: present ? 'PUT' : 'DELETE' }); setSelectedUser(''); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Team membership update failed.') }
  }
  async function removeGrant(grantId: string) {
    try { await request(`/v1/admin/access-grants/${grantId}`, { method: 'DELETE' }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Grant removal failed.') }
  }
  return <><PageHeader title={team.name} description="Team" action={<div className="button-row"><Button to="/teams">All Teams</Button>{canManage ? <Button to={`/teams/${team.team_id}/grants/new`} variant="primary">Grant access</Button> : null}</div>} /><ErrorMessage value={error} /><DetailLayout identity={<IdentityBlock icon={<Users size={30} />} title={team.name} state={<Status tone="positive">Active</Status>} metadata={[["Team ID", <code>{team.team_id}</code>], ["Network ID", <code>{team.network_id}</code>], ["Created", time(team.created_at_unix_seconds)]]} />}>
    <Section title="Members" meta={`${members.length} Users`}>{canManage && available.length ? <div className="inline-editor"><select aria-label="User to add" value={selectedUser} onChange={(event) => setSelectedUser(event.target.value)}><option value="">Choose User</option>{available.map((user) => <option key={user.user_id} value={user.user_id}>{user.name}</option>)}</select><Button disabled={!selectedUser} onClick={() => void changeMember(selectedUser, true)}>Add</Button></div> : null}{members.length ? <div className="resource-list">{members.map((user) => <div className="access-grant-row" key={user.user_id}><ResourceLink to={`/users/${user.user_id}`} icon={<Users size={18} />} title={user.name} />{canManage ? <Button variant="danger" onClick={() => void changeMember(user.user_id, false)}>Remove</Button> : null}</div>)}</div> : <div className="inline-empty">No Users in this Team.</div>}</Section>
    <Section title="Access grants" meta={`${grants.length} shared`}>{grants.length ? <div className="resource-list">{grants.map((grant) => <AccessGrantRow key={grant.grant_id} grant={grant} inventory={inventory} remove={canManage ? removeGrant : undefined} />)}</div> : <div className="inline-empty">No Team grants.</div>}</Section>
  </DetailLayout></>
}

export function LiveCreateGrantPage({ subjectKind }: { subjectKind: 'user' | 'team' }) {
  const { userId, teamId } = useParams()
  const subjectId = subjectKind === 'user' ? userId : teamId
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const [targetKind, setTargetKind] = useState<'network' | 'node' | 'exit'>('network')
  const [nodeId, setNodeId] = useState('')
  const [error, setError] = useState('')
  const activeNodes = (inventory?.nodes ?? []).filter((node) => !liveNodeState(node).inactive)
  const exitIds = new Set((inventory?.routes ?? []).filter((route) => route.kind === 'exit' && route.state === 'approved' && liveRouteState(route).actionable).map((route) => route.node_id))
  const choices = targetKind === 'exit' ? activeNodes.filter((node) => exitIds.has(node.node_id)) : activeNodes
  useEffect(() => { if (targetKind === 'network') setNodeId(''); else if (!choices.some((node) => node.node_id === nodeId)) setNodeId(choices[0]?.node_id ?? '') }, [choices, nodeId, targetKind])
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!inventory?.network || !subjectId || (targetKind !== 'network' && !nodeId)) return setError('Choose a valid access target.')
    try { await request(`/v1/admin/networks/${inventory.network.network_id}/access-grants`, { method: 'POST', body: { subject_kind: subjectKind, subject_id: subjectId, target_kind: targetKind, ...(targetKind === 'network' ? {} : { node_id: nodeId }) } }); await refresh(); navigate(subjectKind === 'user' ? `/users/${subjectId}` : `/teams/${subjectId}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Access grant failed.') }
  }
  return <><PageHeader title="Grant access" description={`Grant this ${subjectKind === 'user' ? 'User' : 'Team'} access within ${inventory?.network?.name ?? 'the selected Network'}`} /><Callout tone="warning">Network access never includes Exit use. Exit must be granted separately.</Callout><FormStack onSubmit={submit}><Field label="Access scope"><select value={targetKind} onChange={(event) => setTargetKind(event.target.value as typeof targetKind)}><option value="network">Entire Network (no Exit)</option><option value="node">One Node only</option><option value="exit">One Exit node</option></select></Field>{targetKind !== 'network' ? <Field label={targetKind === 'exit' ? 'Exit node' : 'Node'}><select value={nodeId} onChange={(event) => setNodeId(event.target.value)}><option value="">Choose node</option>{choices.map((node) => <option key={node.node_id} value={node.node_id}>{node.name || node.node_id}</option>)}</select></Field> : null}<ErrorMessage value={error} /><div className="button-row"><Button type="submit" variant="primary">Grant access</Button><Button to={subjectKind === 'user' ? `/users/${subjectId}` : `/teams/${subjectId}`}>Cancel</Button></div></FormStack></>
}

export function LiveRoutesPage() {
  const { inventory, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const records = inventory?.routes ?? []
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const visibleRecords = visibility === 'all' ? records : records.filter((route) => liveRouteState(route).actionable)
  const columns: DataColumn<ControllerRoute>[] = [
    { key: 'prefix', label: 'Prefix', render: (route) => <code>{route.prefix}</code> },
    { key: 'node', label: 'Node ID', render: (route) => <code>{route.node_id}</code> },
    { key: 'mode', label: 'Mode', render: (route) => liveRouteMode(route.mode) },
    { key: 'state', label: 'State', render: (route) => { const state = liveRouteState(route); return <Status tone={state.tone}>{state.label}</Status> } },
    { key: 'open', label: '', render: (route) => <Button to={`/routes/${route.route_id}`} variant="quiet">View</Button> },
  ]
  return <><PageHeader title="Routes" description="Approved and advertised network prefixes" action={networkId && hasPermission('route.manage', networkId) ? <Button to="/routes/new" variant="primary"><RouteIcon size={16} />Assign route</Button> : undefined} /><VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Current only" visible={visibleRecords.length} total={records.length} /><DataTable columns={columns} rows={visibleRecords} rowKey={(route) => route.route_id} empty={<p>No current routes. Choose All records to view expired, withdrawn, or rejected routes.</p>} /></>
}

export function LiveRouteDetailPage() {
  const { routeId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const route = inventory?.routes.find((candidate) => candidate.route_id === routeId)
  const [error, setError] = useState('')
  if (!route) return <Missing title="Route not found" back="/routes" />
  const activeRoute = route
  const state = liveRouteState(route)
  const canManage = hasPermission('route.manage', route.network_id) && state.actionable
  async function withdraw() { try { await request(`/v1/admin/routes/${activeRoute.route_id}/withdraw`, { method: 'POST' }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Withdrawal failed.') } }
  return <><PageHeader title={route.prefix} action={<div className="button-row">{canManage && route.state === 'advertised' ? <Button to={`/routes/${route.route_id}/approve`} variant="primary">Approve</Button> : null}<Button to="/routes">All routes</Button></div>} /><RecordList rows={[["Route ID", <code>{route.route_id}</code>], ["Node ID", <code>{route.node_id}</code>], ["Mode", liveRouteMode(route.mode)], ["Metric", route.metric], ["State", state.label]]} /><ErrorMessage value={error} />{canManage ? <Button variant="danger" onClick={() => void withdraw()}>Withdraw route</Button> : null}</>
}

export function LiveCreateRoutePage() {
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const eligibleNodes = (inventory?.nodes ?? []).filter((node) => node.revoked_at_unix_seconds === undefined && node.enrollment_class === 'durable')
  const [prefix, setPrefix] = useState('')
  const [nodeId, setNodeId] = useState(eligibleNodes[0]?.node_id ?? '')
  const [mode, setMode] = useState('nat')
  const [metric, setMetric] = useState('100')
  const [error, setError] = useState('')
  useEffect(() => { if (!nodeId && eligibleNodes[0]) setNodeId(eligibleNodes[0].node_id) }, [eligibleNodes, nodeId])
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!inventory?.network || !prefix || !nodeId) return setError('Enter a prefix and choose a node.')
    try { const assigned = await request<ControllerRoute>('/v1/admin/routes/assign', { method: 'POST', body: { network_id: inventory.network.network_id, node_id: nodeId, prefix: prefix.trim(), mode, metric: Number(metric) } }); await refresh(); navigate(`/routes/${assigned.route_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Route assignment failed.') }
  }
  return <><PageHeader title="Assign route" description="Send a network prefix through an enrolled durable node" /><FormStack onSubmit={submit}><Field label="Destination prefix" hint="Use a canonical IPv4 or IPv6 CIDR prefix."><input placeholder="10.20.0.0/16" value={prefix} onChange={(event) => setPrefix(event.target.value)} /></Field><Field label="Forwarding node"><select value={nodeId} onChange={(event) => setNodeId(event.target.value)}>{eligibleNodes.map((node) => <option key={node.node_id} value={node.node_id}>{node.name || node.node_id}</option>)}</select></Field><Field label="Mode"><select value={mode} onChange={(event) => setMode(event.target.value)}><option value="nat">NAT</option><option value="routed">Routed</option></select></Field><Field label="Metric"><input type="number" min="0" value={metric} onChange={(event) => setMetric(event.target.value)} /></Field><ErrorMessage value={error} /><Button type="submit" variant="primary">Assign route</Button></FormStack></>
}

export function LiveApproveRoutePage() {
  const { routeId } = useParams()
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const route = inventory?.routes.find((candidate) => candidate.route_id === routeId)
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  if (!route) return <Missing title="Route not found" back="/routes" />
  if (route.state !== 'advertised' || !liveRouteState(route).actionable) return <PageHeader title="Route is not actionable" action={<Button to={`/routes/${route.route_id}`}>View route</Button>} />
  const activeRoute = route
  async function approve() { try { await request(`/v1/admin/routes/${activeRoute.route_id}/approve`, { method: 'POST' }); await refresh(); navigate(`/routes/${activeRoute.route_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Approval failed.') } }
  return <><PageHeader title="Approve route" description="Confirm this node-advertised prefix" /><RecordList rows={[["Prefix", <code>{route.prefix}</code>], ["Node ID", <code>{route.node_id}</code>]]} /><ActionPanel><Field label={`Type ${route.prefix} to confirm`}><input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></Field><ErrorMessage value={error} /><Button variant="primary" disabled={confirmation !== route.prefix} onClick={() => void approve()}>Approve route</Button></ActionPanel></>
}

export function LiveAccessPage() {
  const { inventory, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const records = inventory?.aclRules ?? []
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const visibleRecords = visibility === 'all' ? records : records.filter((rule) => rule.enabled)
  const columns: DataColumn<ControllerACLRule>[] = [
    { key: 'priority', label: 'Priority', render: (rule) => rule.priority },
    { key: 'rule', label: 'Rule', render: liveACLRuleLabel },
    { key: 'action', label: 'Action', render: (rule) => rule.action },
    { key: 'state', label: 'State', render: (rule) => <Status tone={rule.enabled ? 'positive' : 'muted'}>{rule.enabled ? 'Enabled' : 'Disabled'}</Status> },
    { key: 'open', label: '', render: (rule) => <Button to={`/access/${rule.rule_id}`} variant="quiet">View</Button> },
  ]
  return <><PageHeader title="Access rules" description="Traffic policy evaluated in priority order" action={networkId && hasPermission('acl.manage', networkId) ? <Button to="/access/new" variant="primary"><ShieldCheck size={16} />New rule</Button> : undefined} /><VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Enabled only" visible={visibleRecords.length} total={records.length} /><DataTable columns={columns} rows={visibleRecords} rowKey={(rule) => rule.rule_id} empty={<p>No enabled access rules. Choose All records to view disabled rules.</p>} /></>
}

export function LiveAccessDetailPage() {
  const { ruleId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const rule = inventory?.aclRules.find((candidate) => candidate.rule_id === ruleId)
  const [error, setError] = useState('')
  if (!rule) return <Missing title="Access rule not found" back="/access" />
  const activeRule = rule
  const canManage = hasPermission('acl.manage', rule.network_id)
  async function toggle() { try { await request(`/v1/admin/acl-rules/${activeRule.rule_id}`, { method: 'PUT', body: { priority: activeRule.priority, action: activeRule.action, selector: activeRule.selector, description: activeRule.description, enabled: !activeRule.enabled } }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Rule update failed.') } }
  return <><PageHeader title={liveACLRuleLabel(rule)} action={<Button to="/access">All rules</Button>} /><RecordList rows={[["Rule ID", <code>{rule.rule_id}</code>], ["Description", rule.description || 'Not provided'], ["Priority", rule.priority], ["Action", rule.action], ["Selector", <pre>{JSON.stringify(rule.selector, null, 2)}</pre>]]} /><ErrorMessage value={error} />{canManage ? <Button variant={rule.enabled ? 'danger' : 'primary'} onClick={() => void toggle()}>{rule.enabled ? 'Disable rule' : 'Enable rule'}</Button> : null}</>
}

export function LiveCreateAccessPage() {
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const [description, setDescription] = useState('')
  const [priority, setPriority] = useState('100')
  const [action, setAction] = useState('accept')
  const [selector, setSelector] = useState('{}')
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!inventory?.network) return
    try { const parsed = JSON.parse(selector) as Record<string, unknown>; const created = await request<{ rule_id: string }>(`/v1/admin/networks/${inventory.network.network_id}/acl-rules`, { method: 'POST', body: { description: description.trim(), priority: Number(priority), action, selector: parsed } }); await refresh(); navigate(`/access/${created.rule_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Rule creation failed.') }
  }
  return <><PageHeader title="Create access rule" description="Define a selector, action, and evaluation priority" /><FormStack onSubmit={submit}><Field label="Description"><input placeholder="Allow application traffic" value={description} onChange={(event) => setDescription(event.target.value)} /></Field><Field label="Priority" hint="Lower numbers are evaluated first."><input type="number" min="0" value={priority} onChange={(event) => setPriority(event.target.value)} /></Field><Field label="Action"><select value={action} onChange={(event) => setAction(event.target.value)}><option value="accept">Accept</option><option value="deny">Deny</option></select></Field><Field label="Selector JSON" hint="Use the TrafficSelector fields accepted by the controller."><textarea spellCheck={false} value={selector} onChange={(event) => setSelector(event.target.value)} /></Field><ErrorMessage value={error} /><Button type="submit" variant="primary">Create rule</Button></FormStack></>
}

export function LiveInfrastructurePage() {
  const { inventory, hasPermission } = useControlPlane()
  const network = inventory?.network
  const records = inventory?.relays ?? []
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const visibleRecords = visibility === 'all' ? records : records.filter((relay) => relay.enabled)
  return <><PageHeader title="Infrastructure" description="Network address space and relay services" action={network && hasPermission('relay.manage', network.network_id) ? <Button to="/infrastructure/relays/new" variant="primary"><RadioTower size={16} />Register relay</Button> : undefined} /><VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Enabled relays only" visible={visibleRecords.length} total={records.length} /><div className="infrastructure-grid"><Section title="Network">{network ? <ResourceLink to={`/infrastructure/networks/${network.network_id}`} icon={<Network size={19} />} title={network.name} meta={network.ipv4_pool} /> : <div className="inline-empty">No network.</div>}</Section><Section title="Relays" meta={records.length ? `${records.length} registered` : undefined}>{visibleRecords.length ? <div className="resource-list">{visibleRecords.map((relay) => <ResourceLink key={relay.relay_id} to={`/infrastructure/relays/${relay.relay_id}`} icon={<RadioTower size={19} />} title={relay.name} meta={relay.endpoint} state={<Status tone={relay.enabled ? 'positive' : 'muted'}>{relay.enabled ? 'Enabled' : 'Disabled'}</Status>} />)}</div> : <div className="inline-empty">No enabled relays. Choose All records to view disabled relays.</div>}</Section></div></>
}

export function LiveNetworkPage() {
  const { networkId } = useParams()
  const { inventory, hasPermission, selectNetwork } = useControlPlane()
  const network = inventory?.networks.find((candidate) => candidate.network_id === networkId)
  if (!network) return <Missing title="Network not found" back="/infrastructure" />
  if (inventory?.network?.network_id !== network.network_id) {
    return <PageHeader title={network.name} description="Select this network before opening its resources." action={<Button variant="primary" onClick={() => selectNetwork(network.network_id)}>Select network</Button>} />
  }
  return <><PageHeader title={network.name} description="Network configuration and address allocation" action={<div className="button-row">{hasPermission('route.manage', network.network_id) ? <Button to="/routes/new">Add route</Button> : null}{hasPermission('enrollment.issue', network.network_id) ? <Button to="/nodes/new" variant="primary">Add node</Button> : null}</div>} /><RecordList rows={[["Network ID", <code>{network.network_id}</code>], ["IPv4 pool", <code>{network.ipv4_pool}</code>], ["IPv6 pool", <code>{network.ipv6_pool ?? 'Not configured'}</code>], ["Configuration epoch", network.configuration_epoch]]} /></>
}

export function LiveRelayPage() {
  const { relayId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [serviceId, setServiceId] = useState('')
  const [error, setError] = useState('')
  if (!relayId) {
    async function register(event: FormEvent<HTMLFormElement>) {
      event.preventDefault(); if (!inventory?.network) return
      try { const created = await request<{ relay_id: string }>(`/v1/admin/networks/${inventory.network.network_id}/relays`, { method: 'POST', body: { service_id: serviceId.trim(), name: name.trim(), endpoint: endpoint.trim() } }); await refresh(); navigate(`/infrastructure/relays/${created.relay_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Relay registration failed.') }
    }
    return <><PageHeader title="Register relay" description="Add an authenticated relay endpoint to this network" /><FormStack onSubmit={register}><Field label="Relay name"><input placeholder="relay-east" value={name} onChange={(event) => setName(event.target.value)} /></Field><Field label="Advertised endpoint"><input placeholder="relay.example.com:443" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} /></Field><Field label="Relay service ID"><input value={serviceId} onChange={(event) => setServiceId(event.target.value)} /></Field><ErrorMessage value={error} /><Button type="submit" variant="primary">Register relay</Button></FormStack></>
  }
  const relay = inventory?.relays.find((candidate) => candidate.relay_id === relayId)
  if (!relay) return <Missing title="Relay not found" back="/infrastructure" />
  const activeRelay = relay
  const canManage = hasPermission('relay.manage', relay.network_id)
  async function toggle() { try { if (activeRelay.enabled) await request(`/v1/admin/relays/${activeRelay.relay_id}/disable`, { method: 'POST' }); else await request(`/v1/admin/relays/${activeRelay.relay_id}`, { method: 'PUT', body: { name: activeRelay.name, endpoint: activeRelay.endpoint, enabled: true } }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Relay update failed.') } }
  return <><PageHeader title={relay.name} action={<Button to="/infrastructure">Infrastructure</Button>} /><RecordList rows={[["Relay ID", <code>{relay.relay_id}</code>], ["Service ID", <code>{relay.service_id}</code>], ["Endpoint", <code>{relay.endpoint}</code>], ["State", relay.enabled ? 'Enabled' : 'Disabled']]} /><ErrorMessage value={error} />{canManage ? <Button variant={relay.enabled ? 'danger' : 'primary'} onClick={() => void toggle()}>{relay.enabled ? 'Disable relay' : 'Enable relay'}</Button> : null}</>
}

export function LiveSecurityPage() {
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const [error, setError] = useState('')
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const records = inventory?.certificates ?? []
  const visibleRecords = visibility === 'all' ? records : records.filter((certificate) => liveCertificateState(certificate).label === 'Valid')
  async function revoke(networkId: string, serial: string) { const reason = window.prompt('Revocation reason'); if (!reason) return; try { await request(`/v1/admin/networks/${networkId}/certificates/${serial}/revoke`, { method: 'POST', body: { reason } }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Certificate revocation failed.') } }
  return <><PageHeader title="Security" description="Certificate validity and revocation controls" /><ErrorMessage value={error} /><VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Valid only" visible={visibleRecords.length} total={records.length} /><section className="certificate-grid" aria-label="Certificate inventory">{visibleRecords.length ? visibleRecords.map((certificate) => { const state = liveCertificateState(certificate); return <article key={certificate.certificate_id} className="certificate-card"><header><span className="certificate-card__icon"><FileKey2 aria-hidden="true" size={20} /></span><div><span>Certificate serial</span><h2>{certificate.serial}</h2></div><Status tone={state.tone}>{state.label}</Status></header><RecordList rows={[["Certificate ID", <code>{certificate.certificate_id}</code>], ["Node ID", <code>{certificate.node_id}</code>], ["Valid from", time(certificate.not_before_unix_seconds)], ["Valid until", time(certificate.not_after_unix_seconds)]]} />{state.label !== 'Revoked' && hasPermission('certificate.revoke', certificate.network_id) ? <footer><Button variant="danger" onClick={() => void revoke(certificate.network_id, certificate.serial)}><Ban size={16} />Revoke certificate</Button></footer> : null}</article> }) : <div className="data-empty"><p>No valid certificates. Choose All records to view inactive certificates.</p></div>}</section></>
}

export function auditActor(event: Pick<ControllerAuditEvent, 'actor_kind' | 'actor_id'>) {
  if (event.actor_kind === 'system') return 'System'
  if (event.actor_kind === 'unauthenticated') return 'Unauthenticated'
  if (event.actor_kind === 'legacy_unknown') return 'Legacy actor'
  const label = event.actor_kind === 'administrator' ? 'Administrator' : event.actor_kind === 'service_principal' ? 'Service principal' : event.actor_kind === 'recovery_grant' ? 'Recovery grant' : 'Node'
  return event.actor_id ? `${label} ${event.actor_id}` : label
}

export function LiveAuditPage() {
  const { inventory } = useControlPlane()
  const events = useMemo(() => [...(inventory?.auditEvents ?? [])].sort((left, right) => right.created_at_unix_seconds - left.created_at_unix_seconds), [inventory])
  const columns: DataColumn<ControllerAuditEvent>[] = [
    { key: 'time', label: 'Recorded', render: (event) => time(event.created_at_unix_seconds) },
    { key: 'network', label: 'Network', render: (event) => event.network_id ? <code>{event.network_id}</code> : 'Global' },
    { key: 'actor', label: 'Actor', render: auditActor },
    { key: 'action', label: 'Action', render: (event) => <code>{event.action}</code> },
    { key: 'target', label: 'Target', render: (event) => event.target_id ? <code>{event.target_id}</code> : event.target_type },
  ]
  return <><PageHeader title="Audit events" description="Immutable administrator and controller activity" /><DataTable columns={columns} rows={events} rowKey={(event) => event.event_id} empty={<p>No audit events.</p>} /></>
}
