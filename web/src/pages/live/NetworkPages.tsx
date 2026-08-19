import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { ArrowRight, KeyRound, Link2, LockKeyhole, MonitorDot, Network, Plus, Route as RouteIcon } from 'lucide-react'
import { ActionPanel, Button, Callout, DetailLayout, EmptyState, EntityTitle, Field, FilterSelect, FormStack, IdentityBlock, PageHeader, RecordList, Section, Status, TokenBox, Toolbar, SearchField } from '../../components/ui'
import { controllerOrigin, useControlPlane, type ControllerNetwork, type ControllerNode, type ControllerRoute, type IssuedEnrollmentToken } from '../../lib/control-plane'
import { isCanonicalIpPrefix } from '../../lib/ip-prefix'
import { durableNodeEnrollmentCommand, userEnrollmentCommand } from '../../lib/enrollment-commands'
import { ErrorMessage, Missing, NetworkWorkspaceTabs, emptyNodes, exitNodeCapability, nodeState, routeState, subnetRouterCapability, time, type NetworkWorkspaceView, type RecordVisibility } from './shared'

export function NetworksPage() {
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const [searchParams] = useSearchParams()
  const requestedView = searchParams.get('view')
  const workspaceView: NetworkWorkspaceView = requestedView === 'nodes' || requestedView === 'connectivity' ? requestedView : 'networks'
  const networkId = inventory?.network?.network_id
  const records = inventory?.nodes ?? emptyNodes
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const [networkFilter, setNetworkFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [otherNodes, setOtherNodes] = useState<ControllerNode[]>([])
  const [otherRoutes, setOtherRoutes] = useState<ControllerRoute[]>([])
  const [movingNodeId, setMovingNodeId] = useState('')
  const [moveDestinationId, setMoveDestinationId] = useState('')
  const [creatingNetwork, setCreatingNetwork] = useState(false)
  const [networkName, setNetworkName] = useState('')
  const [ipv4Pool, setIPv4Pool] = useState('')
  const [networkPending, setNetworkPending] = useState(false)
  const [networkError, setNetworkError] = useState('')
  const [creatingConnection, setCreatingConnection] = useState(false)
  const [destinationNetworkId, setDestinationNetworkId] = useState('')
  const [connectionDirection, setConnectionDirection] = useState<'one_way' | 'two_way'>('one_way')
  const allNodes = useMemo(() => [...records, ...otherNodes].filter((node, index, nodes) => nodes.findIndex((candidate) => candidate.node_id === node.node_id) === index), [otherNodes, records])
  const currentNodes = useMemo(() => allNodes.filter((node) => !nodeState(node).inactive), [allNodes])
  const currentNodeIds = useMemo(() => new Set(currentNodes.map((node) => node.node_id)), [currentNodes])
  const allRoutes = useMemo(() => [...(inventory?.routes ?? []), ...otherRoutes].filter((route, index, routes) => routes.findIndex((candidate) => candidate.route_id === route.route_id) === index), [inventory?.routes, otherRoutes])
  const assignedRecords = networkFilter === 'all' ? allNodes : networkFilter === 'unassigned' ? [] : allNodes.filter((node) => node.network_id === networkFilter)
  const currentAssignedRecords = assignedRecords.filter((node) => !nodeState(node).inactive)
  const normalizedQuery = query.trim().toLowerCase()
  const visibleRecords = assignedRecords.filter((node) => (visibility === 'all' || !nodeState(node).inactive) && (!normalizedQuery || [node.name, node.node_id, node.ipv4_address, node.ipv6_address].some((value) => value?.toLowerCase().includes(normalizedQuery))))
  const activeVisibleRecords = visibleRecords.filter((node) => !nodeState(node).inactive)
  const historicalVisibleRecords = visibleRecords.filter((node) => nodeState(node).inactive).sort((left, right) => right.created_at_unix_seconds - left.created_at_unix_seconds)
  const activeRoutes = allRoutes.filter((route) => routeState(route).actionable)
  const networkExits = activeRoutes.filter((route) => route.kind === 'exit' && route.state === 'approved' && currentNodeIds.has(route.node_id))
  const otherNetworks = (inventory?.networks ?? []).filter((network) => network.network_id !== networkId)
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
    if (!otherNetworks.some((network) => network.network_id === destinationNetworkId)) setDestinationNetworkId(otherNetworks[0]?.network_id ?? '')
  }, [destinationNetworkId, otherNetworks])
  useEffect(() => {
    if (!moveDestinations.some((network) => network.network_id === moveDestinationId)) setMoveDestinationId(moveDestinations[0]?.network_id ?? '')
  }, [moveDestinationId, moveDestinations])
  async function createNetwork(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const name = networkName.trim()
    const pool = ipv4Pool.trim()
    if (name.length < 2) return setNetworkError('Enter a network name with at least two characters.')
    if (!isCanonicalIpPrefix(pool, { family: 'ipv4', minBits: 8, maxBits: 30 })) return setNetworkError('Use a canonical, routable IPv4 pool between /8 and /30.')
    if (inventory?.networks.some((network) => network.name.toLowerCase() === name.toLowerCase())) return setNetworkError('A network with this name already exists.')
    setNetworkPending(true); setNetworkError('')
    try {
      await request<ControllerNetwork>('/v1/admin/networks', { method: 'POST', body: { name, ipv4_pool: pool } })
      await refresh()
      setCreatingNetwork(false); setNetworkName(''); setIPv4Pool('')
    } catch (cause) { setNetworkError(cause instanceof Error ? cause.message : 'Could not create the network.') }
    finally { setNetworkPending(false) }
  }
  function routingRole(node: ControllerNode) {
    if (nodeState(node).inactive) return null
    if (networkExits.some((route) => route.node_id === node.node_id)) return <Status tone="positive">Network exit</Status>
    if (node.enabled_capabilities & exitNodeCapability) return <Status tone="warning">Exit eligible</Status>
    if (activeRoutes.some((route) => route.node_id === node.node_id && route.kind === 'subnet') || node.enabled_capabilities & subnetRouterCapability) return 'Subnet router'
    return 'Standard node'
  }
  const workspaceAction = workspaceView === 'networks'
    ? hasPermission('network.create') ? <Button variant="primary" onClick={() => { setCreatingNetwork((value) => !value); setNetworkError('') }}><Plus size={16} />Add network</Button> : undefined
    : workspaceView === 'nodes'
      ? networkId && hasPermission('enrollment.issue', networkId) ? <Button to="/nodes/new" variant="primary"><Plus size={16} />Add node</Button> : undefined
    : otherNetworks.length ? <Button onClick={() => setCreatingConnection((value) => !value)}><Link2 size={16} />Connect network</Button> : undefined
  return <div className="network-workspace-page">
    <PageHeader title="Networks" action={workspaceAction} />
    <NetworkWorkspaceTabs view={workspaceView} networks={inventory?.networks.length ?? 0} nodes={currentNodes.length} />
    {workspaceView === 'networks' && creatingNetwork ? <form className="network-create" onSubmit={createNetwork}>
      <header><div><h2>Create network</h2></div></header>
      <div className="network-create__fields"><Field label="Network name"><input autoFocus maxLength={253} placeholder="Development" value={networkName} onChange={(event) => setNetworkName(event.target.value)} /></Field><Field label="IPv4 address pool" hint="Must not overlap an existing network."><input placeholder="100.97.0.0/16" value={ipv4Pool} onChange={(event) => setIPv4Pool(event.target.value)} /></Field></div>
      <ErrorMessage value={networkError} /><footer className="button-row"><Button type="submit" variant="primary" disabled={networkPending}>{networkPending ? 'Creating…' : 'Create network'}</Button><Button type="button" variant="quiet" disabled={networkPending} onClick={() => setCreatingNetwork(false)}>Cancel</Button></footer>
    </form> : null}
    {inventory?.network ? <>
      {workspaceView === 'networks' ? <section className="network-groups" aria-labelledby="network-groups-title"><header><h2 id="network-groups-title">{inventory.networks.length} {inventory.networks.length === 1 ? 'Network' : 'Networks'}</h2></header><div className="network-group-list">{inventory.networks.map((network) => { const nodes = currentNodes.filter((node) => node.network_id === network.network_id); const exits = networkExits.filter((route) => route.network_id === network.network_id); return <article key={network.network_id}><span className="network-group-list__icon"><Network aria-hidden="true" size={18} /></span><div><strong>{network.name}</strong><code>{network.ipv4_pool}</code></div><div className="network-group-list__stats"><span><strong>{nodes.length}</strong><small>Nodes</small></span><span><strong>{exits.length}</strong><small>{exits.length === 1 ? 'Exit' : 'Exits'}</small></span></div></article> })}</div></section> : null}
      {workspaceView === 'nodes' ? <section className="network-nodes" aria-labelledby="network-nodes-title">
        <header className="network-nodes__header"><div><h2 id="network-nodes-title">Nodes</h2></div></header>
        <Toolbar filters={<><FilterSelect label="Network" value={networkFilter} onChange={setNetworkFilter}><option value="all">All networks</option>{inventory.networks.map((network) => <option key={network.network_id} value={network.network_id}>{network.name}</option>)}<option value="unassigned">Unassigned</option></FilterSelect><FilterSelect label="Record visibility" value={visibility} onChange={(value) => setVisibility(value as RecordVisibility)}><option value="current">Current only</option><option value="all">All records</option></FilterSelect><span className="inventory-result-count" aria-live="polite">{visibleRecords.length} of {visibility === 'all' ? assignedRecords.length : currentAssignedRecords.length} shown</span></>}><SearchField label="Search nodes" placeholder="Search name, address, or node ID" value={query} onChange={setQuery} /></Toolbar>
        {activeVisibleRecords.length ? <div className="node-list" role="list" aria-label="Current nodes">{activeVisibleRecords.map((node) => { const state = nodeState(node); const exitLocked = networkExits.some((route) => route.node_id === node.node_id); return <article className="node-list__row" role="listitem" key={node.node_id}>
          <EntityTitle icon={<MonitorDot size={16} />} subtitle={node.node_id}>{node.name || node.node_id}</EntityTitle>
          <div className="node-list__placement"><span>Placement</span><strong>{inventory.networks.find((network) => network.network_id === node.network_id)?.name ?? 'Unassigned'}</strong><code>{[node.ipv4_address, node.ipv6_address].filter(Boolean).join(' · ') || 'No address'}</code></div>
          <div className="node-list__posture"><span>Role &amp; state</span><div>{routingRole(node)}<Status tone={state.tone}>{state.label}</Status></div><small>{node.enrollment_class} enrollment</small></div>
          <div className="node-list__action">{exitLocked ? <span className="node-move-locked">Exit locked</span> : <Button variant="quiet" onClick={() => setMovingNodeId(node.node_id)}>Move</Button>}</div>
        </article> })}</div> : null}
        {visibility === 'all' && historicalVisibleRecords.length ? <section className="node-history" aria-labelledby="node-history-title"><header><h3 id="node-history-title">History</h3><span>{historicalVisibleRecords.length} inactive</span></header><div role="list">{historicalVisibleRecords.map((node) => { const state = nodeState(node); const network = inventory.networks.find((candidate) => candidate.network_id === node.network_id); return <article className="node-history__row" role="listitem" key={node.node_id}>
          <EntityTitle icon={<MonitorDot size={15} />} subtitle={node.node_id}>{node.name || node.node_id}</EntityTitle>
          <div className="node-history__context"><strong>{network?.name ?? 'Unassigned'}</strong><span>{time(node.created_at_unix_seconds)}</span></div>
          <Status tone={state.tone}>{state.label}</Status>
          <Button to={`/nodes/${node.node_id}`} variant="quiet">View</Button>
        </article> })}</div></section> : null}
        {!visibleRecords.length ? <div className="data-empty">{networkFilter === 'unassigned' ? <><MonitorDot aria-hidden="true" /><h2>No unassigned nodes</h2></> : <p>No nodes match the current filters.</p>}</div> : null}
        {movingNode ? <form className="node-move" onSubmit={(event) => event.preventDefault()}><header><div><span>Move node</span><h3>{movingNode.name || movingNode.node_id}</h3></div><Status tone="muted">Unavailable</Status></header><div className="node-move__path"><strong>{inventory.networks.find((network) => network.network_id === movingNode.network_id)?.name ?? 'Unassigned'}</strong><ArrowRight aria-hidden="true" size={18} /><Field label="Destination network"><select disabled value={moveDestinationId} onChange={(event) => setMoveDestinationId(event.target.value)}>{moveDestinations.map((network) => <option key={network.network_id} value={network.network_id}>{network.name}</option>)}</select></Field></div><Callout tone="warning">Node reassignment is not available in this controller API.</Callout><div className="button-row"><Button type="submit" variant="primary" disabled>Unavailable</Button><Button type="button" variant="quiet" onClick={() => setMovingNodeId('')}>Cancel</Button></div></form> : null}
      </section> : null}
      {workspaceView === 'connectivity' ? <section className="network-connections" aria-labelledby="network-connections-title">
        <header className="network-connections__header">
          <div className="network-connections__title"><span className="network-connections__title-icon"><Link2 aria-hidden="true" size={17} /></span><div><h2 id="network-connections-title">Network connectivity</h2></div></div>
          <div className="network-connections__guardrails" aria-label="Connection availability"><span><LockKeyhole aria-hidden="true" size={13} /> Controller API unavailable</span><span><RouteIcon aria-hidden="true" size={13} /> No connection state reported</span></div>
        </header>
        {creatingConnection ? <form className="network-connection-form" onSubmit={(event) => event.preventDefault()}>
          <header><h3>Connect networks</h3><Status tone="muted">Unavailable</Status></header>
          <div className="network-connection-form__path"><div className="network-endpoint"><small>From</small><strong>{inventory.network.name}</strong><code>{inventory.network.ipv4_pool}</code></div><span className="network-connection-form__arrow"><ArrowRight aria-hidden="true" size={17} /></span><Field label="Destination network"><select disabled value={destinationNetworkId} onChange={(event) => setDestinationNetworkId(event.target.value)}>{otherNetworks.map((network) => <option key={network.network_id} value={network.network_id}>{network.name}</option>)}</select></Field></div>
          <div className="network-connection-form__controls"><Field label="Traffic direction"><select disabled value={connectionDirection} onChange={(event) => setConnectionDirection(event.target.value as typeof connectionDirection)}><option value="one_way">From {inventory.network.name} only</option><option value="two_way">Both networks</option></select></Field><Field label="Initial access"><input readOnly value="Not available" /></Field><Field label="Routes"><input readOnly value="Not available" /></Field></div>
          <Callout tone="warning">Network connection management is not available in this controller API.</Callout><div className="button-row"><Button type="submit" variant="primary" disabled>Unavailable</Button><Button type="button" variant="quiet" onClick={() => setCreatingConnection(false)}>Cancel</Button></div>
        </form> : null}
        {!creatingConnection ? <div className="network-connections__empty"><span><Link2 aria-hidden="true" size={19} /></span><div><strong>Connection data unavailable</strong><p>The controller API does not expose network connections yet.</p></div></div> : null}
      </section> : null}
    </> : <EmptyState icon={<Network />} title="No networks" />}
  </div>
}

export function NodeDetailPage() {
  const { nodeId } = useParams()
  const { inventory, hasPermission } = useControlPlane()
  const node = inventory?.nodes.find((candidate) => candidate.node_id === nodeId)
  if (!node) return <Missing title="Node not found" back="/networks" />
  const state = nodeState(node)
  const canManage = hasPermission('node.manage', node.network_id) && !state.inactive
  const exitRoute = inventory?.routes.find((route) => route.node_id === node.node_id && route.kind === 'exit' && route.state === 'approved' && routeState(route).actionable)
  const subnetRoutes = (inventory?.routes ?? []).filter((route) => route.node_id === node.node_id && route.kind === 'subnet' && routeState(route).actionable)
  const routingRole = exitRoute ? 'Network exit' : node.enabled_capabilities & exitNodeCapability ? 'Eligible for network exit' : subnetRoutes.length || node.enabled_capabilities & subnetRouterCapability ? 'Subnet router' : 'Standard node'
  return <>
    <PageHeader title="Node detail" action={<Button to="/networks" variant="quiet">Back to network</Button>} />
    <DetailLayout identity={<IdentityBlock icon={<MonitorDot size={30} />} title={node.name || node.node_id} state={<Status tone={state.tone}>{state.label}</Status>} actions={canManage ? <><Button to={`/nodes/${node.node_id}/capabilities`}>Capabilities</Button><Button to={`/nodes/${node.node_id}/revoke`} variant="danger">Revoke</Button></> : undefined} metadata={[["Node ID", <code>{node.node_id}</code>], ["Network ID", <code>{node.network_id}</code>], ["Created", time(node.created_at_unix_seconds)]]} />}>
      <Section title="Overlay addresses"><RecordList rows={[["IPv4", <code>{node.ipv4_address ?? 'Not assigned'}</code>], ["IPv6", <code>{node.ipv6_address ?? 'Not assigned'}</code>]]} /></Section>
      <Section title="Network membership"><RecordList rows={[["Network", inventory?.network?.name ?? node.network_id], ["Routing role", routingRole], ["Network exit route", exitRoute ? <code>{exitRoute.prefix}</code> : 'Not assigned'], ["Subnet routes", subnetRoutes.length]]} /></Section>
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
    if (!network || cleanName.length < 2 || (isUserEnrollment && !user)) return setError('Enter a name and choose an available user and network.')
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
    <PageHeader title={isUserEnrollment ? `Enroll a node for ${user?.name ?? 'User'}` : 'Add node'} />
    <FormStack onSubmit={submit}>
      <Field label={isUserEnrollment ? 'Device name' : 'Node name'}><input value={name} onChange={(event) => setName(event.target.value)} autoComplete="off" /></Field>
      {isUserEnrollment ? <><Field label="Enrollment"><select value={kind} onChange={(event) => setKind(event.target.value)}><option value="ephemeral">Ephemeral</option><option value="remembered">Remembered</option></select></Field><Field label="Lease duration (hours)"><input type="number" min="1" max="24" disabled={kind !== 'ephemeral'} value={hours} onChange={(event) => setHours(event.target.value)} /></Field></> : null}
      <Field label="Network"><input readOnly value={inventory?.network?.name ?? 'No network'} /></Field>
      <ErrorMessage value={error} />
      <div className="button-row"><Button type="submit" variant="primary" disabled={pending || !inventory?.network || (isUserEnrollment && !user)}><KeyRound size={16} />{pending ? 'Issuing…' : 'Issue token'}</Button><Button to={isUserEnrollment ? `/users/${userId}` : '/networks'} variant="quiet">Cancel</Button></div>
    </FormStack>
  </>
}

export function AddNodePage() { return <EnrollmentForm /> }
export function UserEnrollmentPage() { const { userId } = useParams(); return <EnrollmentForm userId={userId} /> }

export function TokenPage({ user = false, userId }: { user?: boolean; userId?: string }) {
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

export function NodeCapabilitiesPage() {
  const { nodeId } = useParams()
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const node = inventory?.nodes.find((candidate) => candidate.node_id === nodeId)
  const [mask, setMask] = useState(node?.enabled_capabilities ?? 0)
  const [error, setError] = useState('')
  useEffect(() => { if (node) setMask(node.enabled_capabilities) }, [node])
  if (!node) return <Missing title="Node not found" back="/networks" />
  if (nodeState(node).inactive) return <PageHeader title={nodeState(node).label} action={<Button to={`/nodes/${node.node_id}`}>View node</Button>} />
  const activeNode = node
  async function save() {
    try { await request(`/v1/admin/nodes/${activeNode.node_id}/capabilities`, { method: 'PUT', body: { enabled_capabilities: mask } }); await refresh(); navigate(`/nodes/${activeNode.node_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Update failed.') }
  }
  function setCapability(bit: number, enabled: boolean) { setMask((current) => enabled ? current | bit : current & ~bit) }
  return <><PageHeader title="Routing capabilities" description={`${node.name || node.node_id} in ${inventory?.network?.name ?? 'the selected network'}`} /><ActionPanel><div className="capability-options"><label className="capability-option"><input type="checkbox" checked={Boolean(mask & subnetRouterCapability)} onChange={(event) => setCapability(subnetRouterCapability, event.target.checked)} /><span><strong>Publish subnet routes</strong><small>This node can advertise private destinations in its network.</small></span></label><label className="capability-option"><input type="checkbox" checked={Boolean(mask & exitNodeCapability)} onChange={(event) => setCapability(exitNodeCapability, event.target.checked)} /><span><strong>Eligible for network exit</strong><small>Assign and approve a default route before using this node as an exit.</small></span></label></div><Callout tone="warning">Move the node into this network before enabling routing.</Callout><ErrorMessage value={error} /><div className="button-row"><Button variant="primary" onClick={() => void save()}>Save capabilities</Button><Button to={`/nodes/${node.node_id}`} variant="quiet">Cancel</Button></div></ActionPanel></>
}

export function NodeRevokePage() {
  const { nodeId } = useParams()
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const node = inventory?.nodes.find((candidate) => candidate.node_id === nodeId)
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  if (!node) return <Missing title="Node not found" back="/networks" />
  if (nodeState(node).inactive) return <PageHeader title={nodeState(node).label} action={<Button to={`/nodes/${node.node_id}`}>View node</Button>} />
  const activeNode = node
  async function revoke() {
    try { await request(`/v1/admin/nodes/${activeNode.node_id}/revoke`, { method: 'POST', body: { reason: 'Revoked by administrator' } }); await refresh(); navigate(`/nodes/${activeNode.node_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Revocation failed.') }
  }
  return <><PageHeader title={`Revoke ${node.name || node.node_id}`} /><ActionPanel><Callout tone="danger">This action is permanent.</Callout><Field label={`Type ${node.name || node.node_id} to confirm`}><input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></Field><ErrorMessage value={error} /><Button variant="danger" disabled={confirmation !== (node.name || node.node_id)} onClick={() => void revoke()}>Revoke node</Button></ActionPanel></>
}
