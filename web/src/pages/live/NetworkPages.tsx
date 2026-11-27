import { lazy, Suspense, useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { Clipboard, KeyRound, MonitorDot, Network, Plus } from 'lucide-react'
import { ActionPanel, Button, Callout, DataTable, DetailLayout, EmptyState, EntityTitle, Field, FilterSelect, FormLayout, FormStack, IdentityBlock, PageHeader, RecordList, ReviewPanel, Section, Status, TokenBox, Toolbar, SearchField } from '../../components/ui'
import { controllerOrigin, useControlPlane, type ControllerNetwork, type ControllerNode, type ControllerRoute, type IssuedEnrollmentToken } from '../../lib/control-plane'
import { isCanonicalIpPrefix } from '../../lib/ip-prefix'
import { durableNodeEnrollmentCommand, userEnrollmentCommand } from '../../lib/enrollment-commands'
import { NodePresence, useNodePresence } from './NodePresence'
import { ErrorMessage, Missing, NetworkWorkspaceTabs, emptyNodes, exitNodeCapability, nodeState, routeState, subnetRouterCapability, time, type NetworkWorkspaceView, type RecordVisibility } from './shared'

import '../nodes/node-workspace.css'

const NodeMap = lazy(async () => {
  try {
    const module = await import('./NodeMap')
    return { default: module.NodeMap }
  } catch {
    return { default: () => <div role="alert"><p>The node map could not be loaded.</p><Button onClick={() => window.location.reload()}>Reload map</Button></div> }
  }
})

export function NetworksPage() {
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const presence = useNodePresence((inventory?.networks ?? []).filter(network => hasPermission('node.read', network.network_id)).map(network => network.network_id))
  const [searchParams] = useSearchParams()
  const requestedView = searchParams.get('view')
  const workspaceView: NetworkWorkspaceView = requestedView === 'nodes' || requestedView === 'map' ? requestedView : 'networks'
  const networkId = inventory?.network?.network_id
  const records = inventory?.nodes ?? emptyNodes
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const [networkFilter, setNetworkFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [otherNodes, setOtherNodes] = useState<ControllerNode[]>([])
  const [otherRoutes, setOtherRoutes] = useState<ControllerRoute[]>([])
  const [creatingNetwork, setCreatingNetwork] = useState(false)
  const [networkName, setNetworkName] = useState('')
  const [ipv4Pool, setIPv4Pool] = useState('')
  const [networkPending, setNetworkPending] = useState(false)
  const [networkError, setNetworkError] = useState('')
  const allNodes = useMemo(() => [...records, ...otherNodes].filter((node, index, nodes) => nodes.findIndex((candidate) => candidate.node_id === node.node_id) === index), [otherNodes, records])
  const currentNodes = useMemo(() => allNodes.filter((node) => !nodeState(node).inactive), [allNodes])
  const currentNodeIds = useMemo(() => new Set(currentNodes.map((node) => node.node_id)), [currentNodes])
  const allRoutes = useMemo(() => [...(inventory?.routes ?? []), ...otherRoutes].filter((route, index, routes) => routes.findIndex((candidate) => candidate.route_id === route.route_id) === index), [inventory?.routes, otherRoutes])
  const assignedRecords = networkFilter === 'all' ? allNodes : allNodes.filter((node) => node.network_id === networkFilter)
  const currentAssignedRecords = assignedRecords.filter((node) => !nodeState(node).inactive)
  const normalizedQuery = query.trim().toLowerCase()
  const visibleRecords = assignedRecords.filter((node) => (visibility === 'all' || !nodeState(node).inactive) && (!normalizedQuery || [node.name, node.node_id, node.ipv4_address, node.ipv6_address].some((value) => value?.toLowerCase().includes(normalizedQuery))))
  const activeVisibleRecords = visibleRecords.filter((node) => !nodeState(node).inactive)
  const historicalVisibleRecords = visibleRecords.filter((node) => nodeState(node).inactive).sort((left, right) => right.created_at_unix_seconds - left.created_at_unix_seconds)
  const activeRoutes = allRoutes.filter((route) => routeState(route).actionable)
  const networkExits = activeRoutes.filter((route) => route.kind === 'exit' && route.state === 'approved' && currentNodeIds.has(route.node_id))
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
    : undefined
  return <div className="network-workspace-page">
    <PageHeader title="Networks" action={workspaceAction} />
    <NetworkWorkspaceTabs view={workspaceView} networks={inventory?.networks.length ?? 0} nodes={currentNodes.length} />
    {workspaceView === 'networks' && creatingNetwork ? <form className="network-create" onSubmit={createNetwork}>
      <header><div><h2>Create network</h2></div></header>
      <div className="network-create__fields"><Field label="Network name"><input autoFocus maxLength={253} placeholder="Development" value={networkName} onChange={(event) => setNetworkName(event.target.value)} /></Field><Field label="IPv4 address pool" hint="Must not overlap an existing network."><input placeholder="100.97.0.0/16" value={ipv4Pool} onChange={(event) => setIPv4Pool(event.target.value)} /></Field></div>
      <ErrorMessage value={networkError} /><footer className="button-row"><Button type="submit" variant="primary" disabled={networkPending}>{networkPending ? 'Creating…' : 'Create network'}</Button><Button type="button" variant="quiet" disabled={networkPending} onClick={() => setCreatingNetwork(false)}>Cancel</Button></footer>
    </form> : null}
    {inventory?.network ? <>
      {workspaceView === 'map' && <Suspense fallback={<p role="status">Loading node map…</p>}>
        <NodeMap networks={inventory.networks} />
      </Suspense>}
      {workspaceView === 'networks' && <section className="network-directory" aria-labelledby="network-groups-title">
        <h2 id="network-groups-title">{inventory.networks.length} {inventory.networks.length === 1 ? 'Network' : 'Networks'}</h2>
        <DataTable rows={inventory.networks} rowKey={(network) => network.network_id} columns={[
          { key: 'name', label: 'Network', render: (network) => {
            const name = <span className="network-directory__name"><Network size={16} aria-hidden="true" />{network.name}</span>
            return hasPermission('network.read', network.network_id)
              ? <Link to={`/infrastructure/networks/${network.network_id}`}>{name}</Link> : name
          } },
          { key: 'pool', label: 'IPv4 pool', render: (network) => <code>{network.ipv4_pool}</code> },
          { key: 'nodes', label: 'Nodes', render: (network) => hasPermission('node.read', network.network_id) ? currentNodes.filter((node) => node.network_id === network.network_id).length : 'Unavailable' },
          { key: 'exits', label: 'Exits', render: (network) => hasPermission('node.read', network.network_id) && hasPermission('route.read', network.network_id) ? networkExits.filter((route) => route.network_id === network.network_id).length : 'Unavailable' },
        ]} />
      </section>}
      {workspaceView === 'nodes' ? <section className="network-nodes" aria-labelledby="network-nodes-title">
        <header className="network-nodes__header"><div><h2 id="network-nodes-title">Nodes</h2></div></header>
        <Toolbar filters={<><FilterSelect label="Network" value={networkFilter} onChange={setNetworkFilter}><option value="all">All networks</option>{inventory.networks.map((network) => <option key={network.network_id} value={network.network_id}>{network.name}</option>)}</FilterSelect><FilterSelect label="Record visibility" value={visibility} onChange={(value) => setVisibility(value as RecordVisibility)}><option value="current">Current only</option><option value="all">All records</option></FilterSelect><span className="inventory-result-count" aria-live="polite">{visibleRecords.length} of {visibility === 'all' ? assignedRecords.length : currentAssignedRecords.length} shown</span></>}><SearchField label="Search nodes" placeholder="Search name, address, or node ID" value={query} onChange={setQuery} /></Toolbar>
        {activeVisibleRecords.length > 0 && <div className="node-list-columns" aria-hidden="true"><span>Node</span><span>Placement</span><span>Connection</span><span /></div>}
        {activeVisibleRecords.length ? <div className="node-list" role="list" aria-label="Current nodes">{activeVisibleRecords.map((node) => <article className="node-list__row" role="listitem" key={node.node_id}>
          <EntityTitle icon={<MonitorDot size={16} />} subtitle={node.node_id}>{node.name || node.node_id}</EntityTitle>
          <div className="node-list__placement"><span>Placement</span><strong>{inventory.networks.find((network) => network.network_id === node.network_id)?.name ?? 'Unassigned'}</strong><code>{[node.ipv4_address, node.ipv6_address].filter(Boolean).join(' · ') || 'No address'}</code></div>
          <div className="node-list__posture"><span>Connection</span><div>{routingRole(node)}</div><NodePresence record={presence.records[node.node_id]} unavailable={presence.unavailable} /></div>
          {node.network_id === networkId && <div className="node-list__action"><Button to={`/nodes/${node.node_id}`} variant="quiet">View</Button></div>}
        </article>)}</div> : null}
        {visibility === 'all' && historicalVisibleRecords.length ? <section className="node-history" aria-labelledby="node-history-title"><header><h3 id="node-history-title">History</h3><span>{historicalVisibleRecords.length} inactive</span></header><div role="list">{historicalVisibleRecords.map((node) => { const state = nodeState(node); const network = inventory.networks.find((candidate) => candidate.network_id === node.network_id); return <article className="node-history__row" role="listitem" key={node.node_id}>
          <EntityTitle icon={<MonitorDot size={15} />} subtitle={node.node_id}>{node.name || node.node_id}</EntityTitle>
          <div className="node-history__context"><strong>{network?.name ?? 'Unassigned'}</strong><span>{time(node.created_at_unix_seconds)}</span></div>
          <Status tone={state.tone}>{state.label}</Status>
          {node.network_id === networkId && <Button to={`/nodes/${node.node_id}`} variant="quiet">View</Button>}
        </article> })}</div></section> : null}
        {!visibleRecords.length ? <div className="data-empty"><p>No nodes match these filters.</p></div> : null}
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
  return <div className="node-detail-workspace">
    <PageHeader title="Node detail" action={<Button to="/networks?view=nodes" variant="quiet">Back to network</Button>} />
    <DetailLayout identity={<IdentityBlock icon={<MonitorDot size={30} />} title={node.name || node.node_id} state={<Status tone={state.tone}>{state.label}</Status>} actions={canManage ? <><Button to={`/nodes/${node.node_id}/capabilities`}>Capabilities</Button><Button to={`/nodes/${node.node_id}/revoke`} variant="danger">Revoke</Button></> : undefined} metadata={[["Node ID", <code>{node.node_id}</code>], ["Network ID", <code>{node.network_id}</code>], ["Created", time(node.created_at_unix_seconds)]]} />}>
      <Section title="Overlay addresses"><RecordList rows={[["IPv4", <code>{node.ipv4_address ?? 'Not assigned'}</code>], ["IPv6", <code>{node.ipv6_address ?? 'Not assigned'}</code>]]} /></Section>
      <Section title="Network membership"><RecordList rows={[["Network", inventory?.network?.name ?? node.network_id], ["Routing role", routingRole], ["Network exit route", exitRoute ? <code>{exitRoute.prefix}</code> : 'Not assigned'], ["Subnet routes", subnetRoutes.length]]} /></Section>
    </DetailLayout>
  </div>
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
  return <div className="node-editor-workspace">
    <PageHeader title={isUserEnrollment ? `Enroll a node for ${user?.name ?? 'User'}` : 'Add node'} />
    <FormLayout form={<FormStack onSubmit={submit}>
      <Field label={isUserEnrollment ? 'Device name' : 'Node name'}><input value={name} onChange={(event) => setName(event.target.value)} autoComplete="off" /></Field>
      {isUserEnrollment ? <><Field label="Enrollment"><select value={kind} onChange={(event) => setKind(event.target.value)}><option value="ephemeral">Ephemeral</option><option value="remembered">Remembered</option></select></Field><Field label="Lease duration (hours)"><input type="number" min="1" max="24" disabled={kind !== 'ephemeral'} value={hours} onChange={(event) => setHours(event.target.value)} /></Field></> : null}
      <Field label="Network"><input readOnly value={inventory?.network?.name ?? 'No network'} /></Field>
      <ErrorMessage value={error} />
      <div className="button-row"><Button type="submit" variant="primary" disabled={pending || !inventory?.network || (isUserEnrollment && !user)}><KeyRound size={16} />{pending ? 'Issuing…' : 'Issue token'}</Button><Button to={isUserEnrollment ? `/users/${userId}` : '/networks'} variant="quiet">Cancel</Button></div>
    </FormStack>} review={<ReviewPanel title="Enrollment review" rows={[
      ['Network', inventory?.network?.name ?? 'No network'],
      ...(isUserEnrollment ? [['User', user?.name ?? 'Unavailable'] as [string, string]] : []),
      ['Enrollment class', kind === 'durable' ? 'Durable' : kind === 'ephemeral' ? 'Ephemeral' : 'Remembered'],
      ['Token expires', isUserEnrollment ? '15 minutes' : '24 hours'],
      ['Redemptions', 'One'],
    ]} />} />
  </div>
}

export function AddNodePage() { return <EnrollmentForm /> }
export function UserEnrollmentPage() { const { userId } = useParams(); return <EnrollmentForm userId={userId} /> }

export function TokenPage({ user = false, userId }: { user?: boolean; userId?: string }) {
  const { peekIssuedEnrollmentToken, clearIssuedEnrollmentToken, isSessionBindingCurrent } = useControlPlane()
  const [copyStatus, setCopyStatus] = useState('')
  const [issued] = useState(() => peekIssuedEnrollmentToken())
  useEffect(() => {
    if (issued) clearIssuedEnrollmentToken(issued.binding)
  }, [clearIssuedEnrollmentToken, issued])
  if (!issued || !isSessionBindingCurrent(issued.binding) || issued.value.kind !== 'command') return <Missing title="Token unavailable" back={userId ? `/users/${userId}/enroll` : user ? '/users/new' : '/nodes/new'} />
  const token = issued.value
  async function copyToken() {
    try { await navigator.clipboard.writeText(token.token); setCopyStatus('Token copied.') }
    catch { setCopyStatus('Select the token and copy it manually.') }
  }
  return <div className="node-token-workspace">
    <PageHeader title={token.heading} />
    <Callout tone="warning">Copy this single-use token now.</Callout>
    <TokenBox label="Enrollment token" value={token.token}><Button onClick={() => void copyToken()}><Clipboard size={15} aria-hidden="true" />Copy token</Button></TokenBox>
    {copyStatus && <p role="status">{copyStatus}</p>}
    <Section title="Command"><pre tabIndex={0}><code>{token.command}</code></pre></Section>
    <Button to={user ? '/users' : '/networks'} variant="primary">Done</Button>
  </div>
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
  return <div className="node-editor-workspace"><PageHeader title="Routing capabilities" description={`${node.name || node.node_id} in ${inventory?.network?.name ?? 'the selected network'}`} /><ActionPanel><div className="capability-options"><label className="capability-option"><input type="checkbox" checked={Boolean(mask & subnetRouterCapability)} onChange={(event) => setCapability(subnetRouterCapability, event.target.checked)} /><span><strong>Publish subnet routes</strong><small>This node can advertise private destinations in its network.</small></span></label><label className="capability-option"><input type="checkbox" checked={Boolean(mask & exitNodeCapability)} onChange={(event) => setCapability(exitNodeCapability, event.target.checked)} /><span><strong>Eligible for network exit</strong><small>Assign and approve a default route before using this node as an exit.</small></span></label></div><Callout tone="warning">Move the node into this network before enabling routing.</Callout><ErrorMessage value={error} /><div className="button-row"><Button variant="primary" onClick={() => void save()}>Save capabilities</Button><Button to={`/nodes/${node.node_id}`} variant="quiet">Cancel</Button></div></ActionPanel></div>
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
  return <div className="node-editor-workspace"><PageHeader title={`Revoke ${node.name || node.node_id}`} /><ActionPanel><Callout tone="danger">This action is permanent.</Callout><Field label={`Type ${node.name || node.node_id} to confirm`}><input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></Field><ErrorMessage value={error} /><div className="button-row"><Button variant="danger" disabled={confirmation !== (node.name || node.node_id)} onClick={() => void revoke()}>Revoke node</Button><Button variant="quiet" to={`/nodes/${node.node_id}`}>Cancel</Button></div></ActionPanel></div>
}
