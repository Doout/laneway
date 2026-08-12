import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Ban, KeyRound, MonitorDot, Network, Plus, RadioTower, Route as RouteIcon, ShieldCheck, TriangleAlert, Users } from 'lucide-react'
import { Button, Callout, DataTable, DetailLayout, EmptyState, EntityTitle, Field, FormStack, IdentityBlock, PageHeader, Section, Status, TokenBox, type DataColumn } from '../../components/ui'
import { controllerOrigin, useControlPlane, type ControllerACLRule, type ControllerAuditEvent, type ControllerCertificate, type ControllerNode, type ControllerRoute, type IssuedEnrollmentToken } from '../../lib/control-plane'
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

export function LiveOverviewPage() {
  const { inventory, inventoryPending, inventoryError, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const rows = [
    ['Nodes', inventory?.nodes.length ?? 0, 'node.read'],
    ['Routes', inventory?.routes.length ?? 0, 'route.read'],
    ['Access rules', inventory?.aclRules.length ?? 0, 'acl.read'],
    ['Relays', inventory?.relays.length ?? 0, 'relay.read'],
  ] as const
  return <>
    <PageHeader title="Overview" description={inventory?.network?.name} />
    <ErrorMessage value={inventoryError} />
    {inventoryPending ? <p role="status">Refreshing inventory…</p> : null}
    {inventory && inventory.networks.length > 1 && !inventory.network ? <Callout>Select a network.</Callout> : null}
    {inventory ? <section className="overview-metrics" aria-label="Network inventory summary">
      {rows.filter(([, , permission]) => Boolean(networkId && hasPermission(permission, networkId))).map(([label, count]) => <div key={label}><span><strong>{count}</strong>{label}</span></div>)}
    </section> : null}
  </>
}

export function LiveNodesPage() {
  const { inventory, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const columns: DataColumn<ControllerNode>[] = [
    { key: 'node', label: 'Node', render: (node) => <EntityTitle icon={<MonitorDot size={16} />} subtitle={node.node_id}>{node.name || node.node_id}</EntityTitle> },
    { key: 'class', label: 'Enrollment', render: (node) => node.enrollment_class },
    { key: 'address', label: 'Address', render: (node) => <code>{[node.ipv4_address, node.ipv6_address].filter(Boolean).join(' · ') || 'Not assigned'}</code> },
    { key: 'state', label: 'State', render: (node) => { const state = liveNodeState(node); return <Status tone={state.tone}>{state.label}</Status> } },
    { key: 'open', label: '', render: (node) => <Button to={`/nodes/${node.node_id}`} variant="quiet">View</Button> },
  ]
  return <>
    <PageHeader title="Nodes" action={networkId && hasPermission('enrollment.issue', networkId) ? <Button to="/nodes/new" variant="primary"><Plus size={16} />Add node</Button> : undefined} />
    <DataTable columns={columns} rows={inventory?.nodes ?? []} rowKey={(node) => node.node_id} empty={<p>No nodes.</p>} />
  </>
}

export function LiveNodeDetailPage() {
  const { nodeId } = useParams()
  const { inventory, hasPermission } = useControlPlane()
  const node = inventory?.nodes.find((candidate) => candidate.node_id === nodeId)
  if (!node) return <Missing title="Node not found" back="/nodes" />
  const state = liveNodeState(node)
  const canManage = hasPermission('node.manage', node.network_id) && !state.inactive
  return <>
    <PageHeader title="Node" action={<Button to="/nodes" variant="quiet">All nodes</Button>} />
    <DetailLayout identity={<IdentityBlock icon={<MonitorDot size={30} />} title={node.name || node.node_id} state={<Status tone={state.tone}>{state.label}</Status>} actions={canManage ? <><Button to={`/nodes/${node.node_id}/capabilities`}>Capabilities</Button><Button to={`/nodes/${node.node_id}/revoke`} variant="danger">Revoke</Button></> : undefined} metadata={[["Node ID", <code>{node.node_id}</code>], ["Network ID", <code>{node.network_id}</code>], ["Created", time(node.created_at_unix_seconds)]]} />}>
      <Section title="Overlay addresses"><dl><div><dt>IPv4</dt><dd><code>{node.ipv4_address ?? 'Not assigned'}</code></dd></div><div><dt>IPv6</dt><dd><code>{node.ipv6_address ?? 'Not assigned'}</code></dd></div></dl></Section>
      <Section title="Capabilities"><code>{node.enabled_capabilities}</code></Section>
    </DetailLayout>
  </>
}

function EnrollmentForm({ user }: { user: boolean }) {
  const { inventory, request, captureSessionBinding, storeIssuedEnrollmentToken } = useControlPlane()
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [kind, setKind] = useState(user ? 'ephemeral' : 'durable')
  const [hours, setHours] = useState('8')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const network = inventory?.network
    const cleanName = name.trim()
    if (!network || cleanName.length < 2) return setError('Enter a name and choose an available network.')
    const sessionBinding = captureSessionBinding()
    if (!sessionBinding) return setError('The administrator session changed. Try again.')
    setPending(true); setError('')
    try {
      const result = await request<{ enrollment_token: string }>('/v1/admin/enrollment-tokens', { method: 'POST', body: {
        network_id: network.network_id,
        label: cleanName,
        requested_name: cleanName,
        expires_at_unix_seconds: Math.floor(Date.now() / 1000) + (user ? 900 : 86_400),
        enrollment_class: kind,
        ...(user ? { session_lifetime_seconds: kind === 'ephemeral' ? Number(hours) * 3600 : 0 } : { enabled_capabilities: 0 }),
      } })
      const host = new URL(controllerOrigin()).host
      if (typeof result.enrollment_token !== 'string' || result.enrollment_token.length === 0) throw new Error('The controller returned an invalid enrollment token.')
      const issued: IssuedEnrollmentToken = {
        kind: 'command',
        token: result.enrollment_token,
        heading: user ? 'User token issued' : 'Node token issued',
        command: user
          ? userEnrollmentCommand(host, kind === 'ephemeral' ? 'Ephemeral' : 'Remembered')
          : durableNodeEnrollmentCommand(host),
      }
      if (!storeIssuedEnrollmentToken(sessionBinding, issued)) throw new Error('The administrator session changed before the token could be shown.')
      navigate(user ? '/users/new/token' : '/nodes/new/token')
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Token issuance failed.') } finally { setPending(false) }
  }
  return <>
    <PageHeader title={user ? 'Issue user access' : 'Add node'} />
    <FormStack onSubmit={submit}>
      <Field label={user ? 'Requested node name' : 'Node name'}><input value={name} onChange={(event) => setName(event.target.value)} autoComplete="off" /></Field>
      {user ? <><Field label="Enrollment"><select value={kind} onChange={(event) => setKind(event.target.value)}><option value="ephemeral">Ephemeral</option><option value="remembered">Remembered</option></select></Field><Field label="Lease duration (hours)"><input type="number" min="1" max="24" disabled={kind !== 'ephemeral'} value={hours} onChange={(event) => setHours(event.target.value)} /></Field></> : null}
      <Field label="Network"><input readOnly value={inventory?.network?.name ?? 'No network'} /></Field>
      <ErrorMessage value={error} />
      <div className="button-row"><Button type="submit" variant="primary" disabled={pending || !inventory?.network}><KeyRound size={16} />{pending ? 'Issuing…' : 'Issue token'}</Button><Button to={user ? '/users' : '/nodes'} variant="quiet">Cancel</Button></div>
    </FormStack>
  </>
}

export function LiveAddNodePage() { return <EnrollmentForm user={false} /> }
export function LiveIssueUserPage() { return <EnrollmentForm user /> }

export function LiveTokenPage({ user }: { user: boolean }) {
  const { peekIssuedEnrollmentToken, clearIssuedEnrollmentToken, isSessionBindingCurrent } = useControlPlane()
  const [issued] = useState(() => peekIssuedEnrollmentToken())
  useEffect(() => {
    if (issued) clearIssuedEnrollmentToken(issued.binding)
  }, [clearIssuedEnrollmentToken, issued])
  if (!issued || !isSessionBindingCurrent(issued.binding) || issued.value.kind !== 'command') return <Missing title="Token unavailable" back={user ? '/users/new' : '/nodes/new'} />
  const token = issued.value
  return <>
    <PageHeader title={token.heading} />
    <Callout tone="warning">Copy this single-use token now.</Callout>
    <TokenBox label="Enrollment token" value={token.token} />
    <Section title="Command"><pre><code>{token.command}</code></pre></Section>
    <Button to={user ? '/users' : '/nodes'} variant="primary">Done</Button>
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
  if (!node) return <Missing title="Node not found" back="/nodes" />
  if (liveNodeState(node).inactive) return <PageHeader title={liveNodeState(node).label} action={<Button to={`/nodes/${node.node_id}`}>View node</Button>} />
  const activeNode = node
  async function save() {
    try { await request(`/v1/admin/nodes/${activeNode.node_id}/capabilities`, { method: 'PUT', body: { enabled_capabilities: mask } }); await refresh(); navigate(`/nodes/${activeNode.node_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Update failed.') }
  }
  return <><PageHeader title="Edit capabilities" /><Field label="Capability mask"><input type="number" min="0" value={mask} onChange={(event) => setMask(Number(event.target.value))} /></Field><ErrorMessage value={error} /><div className="button-row"><Button variant="primary" onClick={() => void save()}>Save</Button><Button to={`/nodes/${node.node_id}`} variant="quiet">Cancel</Button></div></>
}

export function LiveNodeRevokePage() {
  const { nodeId } = useParams()
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const node = inventory?.nodes.find((candidate) => candidate.node_id === nodeId)
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  if (!node) return <Missing title="Node not found" back="/nodes" />
  if (liveNodeState(node).inactive) return <PageHeader title={liveNodeState(node).label} action={<Button to={`/nodes/${node.node_id}`}>View node</Button>} />
  const activeNode = node
  async function revoke() {
    try { await request(`/v1/admin/nodes/${activeNode.node_id}/revoke`, { method: 'POST', body: { reason: 'Revoked by administrator' } }); await refresh(); navigate(`/nodes/${activeNode.node_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Revocation failed.') }
  }
  return <><PageHeader title={`Revoke ${node.name || node.node_id}`} /><Callout tone="danger">This action is permanent.</Callout><Field label={`Type ${node.name || node.node_id} to confirm`}><input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></Field><ErrorMessage value={error} /><Button variant="danger" disabled={confirmation !== (node.name || node.node_id)} onClick={() => void revoke()}>Revoke node</Button></>
}

export function LiveUsersPage() {
  const { inventory, hasPermission } = useControlPlane()
  const records = (inventory?.nodes ?? []).filter((node) => node.enrollment_class !== 'durable')
  const networkId = inventory?.network?.network_id
  const columns: DataColumn<ControllerNode>[] = [
    { key: 'user', label: 'User enrollment', render: (node) => <EntityTitle icon={<Users size={16} />} subtitle={node.node_id}>{node.name || node.node_id}</EntityTitle> },
    { key: 'class', label: 'Type', render: (node) => node.enrollment_class },
    { key: 'lease', label: 'Lease expires', render: (node) => time(node.lease_expires_at_unix_seconds) },
    { key: 'state', label: 'State', render: (node) => { const state = liveNodeState(node); return <Status tone={state.tone}>{state.label}</Status> } },
    { key: 'open', label: '', render: (node) => <Button to={`/users/${node.node_id}`} variant="quiet">View</Button> },
  ]
  return <><PageHeader title="Users" action={networkId && hasPermission('enrollment.issue', networkId) ? <Button to="/users/new" variant="primary">Issue access</Button> : undefined} /><DataTable columns={columns} rows={records} rowKey={(node) => node.node_id} empty={<p>No user enrollments.</p>} /></>
}

export function LiveUserDetailPage() {
  const { userId } = useParams()
  const { inventory } = useControlPlane()
  const node = inventory?.nodes.find((candidate) => candidate.node_id === userId && candidate.enrollment_class !== 'durable')
  if (!node) return <Missing title="User enrollment not found" back="/users" />
  const state = liveNodeState(node)
  return <><PageHeader title="User enrollment" action={<Button to="/users">All users</Button>} /><dl><div><dt>Name</dt><dd>{node.name || node.node_id}</dd></div><div><dt>Node ID</dt><dd><code>{node.node_id}</code></dd></div><div><dt>Enrollment</dt><dd>{node.enrollment_class}</dd></div><div><dt>State</dt><dd><Status tone={state.tone}>{state.label}</Status></dd></div><div><dt>Lease expires</dt><dd>{time(node.lease_expires_at_unix_seconds)}</dd></div></dl></>
}

export function LiveRoutesPage() {
  const { inventory, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const columns: DataColumn<ControllerRoute>[] = [
    { key: 'prefix', label: 'Prefix', render: (route) => <code>{route.prefix}</code> },
    { key: 'node', label: 'Node ID', render: (route) => <code>{route.node_id}</code> },
    { key: 'mode', label: 'Mode', render: (route) => liveRouteMode(route.mode) },
    { key: 'state', label: 'State', render: (route) => { const state = liveRouteState(route); return <Status tone={state.tone}>{state.label}</Status> } },
    { key: 'open', label: '', render: (route) => <Button to={`/routes/${route.route_id}`} variant="quiet">View</Button> },
  ]
  return <><PageHeader title="Routes" action={networkId && hasPermission('route.manage', networkId) ? <Button to="/routes/new" variant="primary"><RouteIcon size={16} />Assign route</Button> : undefined} /><DataTable columns={columns} rows={inventory?.routes ?? []} rowKey={(route) => route.route_id} empty={<p>No routes.</p>} /></>
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
  return <><PageHeader title={route.prefix} action={<div className="button-row">{canManage && route.state === 'advertised' ? <Button to={`/routes/${route.route_id}/approve`} variant="primary">Approve</Button> : null}<Button to="/routes">All routes</Button></div>} /><dl><div><dt>Route ID</dt><dd><code>{route.route_id}</code></dd></div><div><dt>Node ID</dt><dd><code>{route.node_id}</code></dd></div><div><dt>Mode</dt><dd>{liveRouteMode(route.mode)}</dd></div><div><dt>Metric</dt><dd>{route.metric}</dd></div><div><dt>State</dt><dd>{state.label}</dd></div></dl><ErrorMessage value={error} />{canManage ? <Button variant="danger" onClick={() => void withdraw()}>Withdraw route</Button> : null}</>
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
  return <><PageHeader title="Assign route" /><FormStack onSubmit={submit}><Field label="Destination prefix"><input value={prefix} onChange={(event) => setPrefix(event.target.value)} /></Field><Field label="Forwarding node"><select value={nodeId} onChange={(event) => setNodeId(event.target.value)}>{eligibleNodes.map((node) => <option key={node.node_id} value={node.node_id}>{node.name || node.node_id}</option>)}</select></Field><Field label="Mode"><select value={mode} onChange={(event) => setMode(event.target.value)}><option value="nat">NAT</option><option value="routed">Routed</option></select></Field><Field label="Metric"><input type="number" min="0" value={metric} onChange={(event) => setMetric(event.target.value)} /></Field><ErrorMessage value={error} /><Button type="submit" variant="primary">Assign route</Button></FormStack></>
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
  return <><PageHeader title="Approve route" /><dl><div><dt>Prefix</dt><dd><code>{route.prefix}</code></dd></div><div><dt>Node ID</dt><dd><code>{route.node_id}</code></dd></div></dl><Field label={`Type ${route.prefix} to confirm`}><input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></Field><ErrorMessage value={error} /><Button variant="primary" disabled={confirmation !== route.prefix} onClick={() => void approve()}>Approve route</Button></>
}

export function LiveAccessPage() {
  const { inventory, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const columns: DataColumn<ControllerACLRule>[] = [
    { key: 'priority', label: 'Priority', render: (rule) => rule.priority },
    { key: 'rule', label: 'Rule', render: liveACLRuleLabel },
    { key: 'action', label: 'Action', render: (rule) => rule.action },
    { key: 'state', label: 'State', render: (rule) => <Status tone={rule.enabled ? 'positive' : 'muted'}>{rule.enabled ? 'Enabled' : 'Disabled'}</Status> },
    { key: 'open', label: '', render: (rule) => <Button to={`/access/${rule.rule_id}`} variant="quiet">View</Button> },
  ]
  return <><PageHeader title="Access rules" action={networkId && hasPermission('acl.manage', networkId) ? <Button to="/access/new" variant="primary"><ShieldCheck size={16} />New rule</Button> : undefined} /><DataTable columns={columns} rows={inventory?.aclRules ?? []} rowKey={(rule) => rule.rule_id} empty={<p>No access rules.</p>} /></>
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
  return <><PageHeader title={liveACLRuleLabel(rule)} action={<Button to="/access">All rules</Button>} /><dl><div><dt>Rule ID</dt><dd><code>{rule.rule_id}</code></dd></div><div><dt>Description</dt><dd>{rule.description || 'Not provided'}</dd></div><div><dt>Priority</dt><dd>{rule.priority}</dd></div><div><dt>Action</dt><dd>{rule.action}</dd></div><div><dt>Selector</dt><dd><pre>{JSON.stringify(rule.selector, null, 2)}</pre></dd></div></dl><ErrorMessage value={error} />{canManage ? <Button variant={rule.enabled ? 'danger' : 'primary'} onClick={() => void toggle()}>{rule.enabled ? 'Disable rule' : 'Enable rule'}</Button> : null}</>
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
  return <><PageHeader title="Create access rule" /><FormStack onSubmit={submit}><Field label="Description"><input value={description} onChange={(event) => setDescription(event.target.value)} /></Field><Field label="Priority"><input type="number" min="0" value={priority} onChange={(event) => setPriority(event.target.value)} /></Field><Field label="Action"><select value={action} onChange={(event) => setAction(event.target.value)}><option value="accept">Accept</option><option value="deny">Deny</option></select></Field><Field label="Selector JSON"><textarea value={selector} onChange={(event) => setSelector(event.target.value)} /></Field><ErrorMessage value={error} /><Button type="submit" variant="primary">Create rule</Button></FormStack></>
}

export function LiveInfrastructurePage() {
  const { inventory, hasPermission } = useControlPlane()
  const network = inventory?.network
  return <><PageHeader title="Infrastructure" action={network && hasPermission('relay.manage', network.network_id) ? <Button to="/infrastructure/relays/new" variant="primary"><RadioTower size={16} />Register relay</Button> : undefined} />{network ? <Section title="Network"><Button to={`/infrastructure/networks/${network.network_id}`} variant="quiet"><Network size={16} />{network.name}</Button></Section> : <p>No network.</p>}<Section title="Relays">{inventory?.relays.length ? inventory.relays.map((relay) => <div key={relay.relay_id}><Button to={`/infrastructure/relays/${relay.relay_id}`} variant="quiet">{relay.name}</Button><Status tone={relay.enabled ? 'positive' : 'muted'}>{relay.enabled ? 'Enabled' : 'Disabled'}</Status></div>) : <p>No relays.</p>}</Section></>
}

export function LiveNetworkPage() {
  const { networkId } = useParams()
  const { inventory, hasPermission, selectNetwork } = useControlPlane()
  const network = inventory?.networks.find((candidate) => candidate.network_id === networkId)
  if (!network) return <Missing title="Network not found" back="/infrastructure" />
  if (inventory?.network?.network_id !== network.network_id) {
    return <PageHeader title={network.name} description="Select this network before opening its resources." action={<Button variant="primary" onClick={() => selectNetwork(network.network_id)}>Select network</Button>} />
  }
  return <><PageHeader title={network.name} action={<div className="button-row">{hasPermission('route.manage', network.network_id) ? <Button to="/routes/new">Add route</Button> : null}{hasPermission('enrollment.issue', network.network_id) ? <Button to="/nodes/new" variant="primary">Add node</Button> : null}</div>} /><dl><div><dt>Network ID</dt><dd><code>{network.network_id}</code></dd></div><div><dt>IPv4 pool</dt><dd><code>{network.ipv4_pool}</code></dd></div><div><dt>IPv6 pool</dt><dd><code>{network.ipv6_pool ?? 'Not configured'}</code></dd></div><div><dt>Configuration epoch</dt><dd>{network.configuration_epoch}</dd></div></dl></>
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
    return <><PageHeader title="Register relay" /><FormStack onSubmit={register}><Field label="Relay name"><input value={name} onChange={(event) => setName(event.target.value)} /></Field><Field label="Advertised endpoint"><input value={endpoint} onChange={(event) => setEndpoint(event.target.value)} /></Field><Field label="Relay service ID"><input value={serviceId} onChange={(event) => setServiceId(event.target.value)} /></Field><ErrorMessage value={error} /><Button type="submit" variant="primary">Register relay</Button></FormStack></>
  }
  const relay = inventory?.relays.find((candidate) => candidate.relay_id === relayId)
  if (!relay) return <Missing title="Relay not found" back="/infrastructure" />
  const activeRelay = relay
  const canManage = hasPermission('relay.manage', relay.network_id)
  async function toggle() { try { if (activeRelay.enabled) await request(`/v1/admin/relays/${activeRelay.relay_id}/disable`, { method: 'POST' }); else await request(`/v1/admin/relays/${activeRelay.relay_id}`, { method: 'PUT', body: { name: activeRelay.name, endpoint: activeRelay.endpoint, enabled: true } }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Relay update failed.') } }
  return <><PageHeader title={relay.name} action={<Button to="/infrastructure">Infrastructure</Button>} /><dl><div><dt>Relay ID</dt><dd><code>{relay.relay_id}</code></dd></div><div><dt>Service ID</dt><dd><code>{relay.service_id}</code></dd></div><div><dt>Endpoint</dt><dd><code>{relay.endpoint}</code></dd></div><div><dt>State</dt><dd>{relay.enabled ? 'Enabled' : 'Disabled'}</dd></div></dl><ErrorMessage value={error} />{canManage ? <Button variant={relay.enabled ? 'danger' : 'primary'} onClick={() => void toggle()}>{relay.enabled ? 'Disable relay' : 'Enable relay'}</Button> : null}</>
}

export function LiveSecurityPage() {
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const [error, setError] = useState('')
  async function revoke(networkId: string, serial: string) { const reason = window.prompt('Revocation reason'); if (!reason) return; try { await request(`/v1/admin/networks/${networkId}/certificates/${serial}/revoke`, { method: 'POST', body: { reason } }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Certificate revocation failed.') } }
  return <><PageHeader title="Security" /><ErrorMessage value={error} /><section aria-label="Certificate inventory">{inventory?.certificates.length ? inventory.certificates.map((certificate) => { const state = liveCertificateState(certificate); return <div key={certificate.certificate_id} className="section"><h2>{certificate.serial}</h2><dl><div><dt>Certificate ID</dt><dd><code>{certificate.certificate_id}</code></dd></div><div><dt>Node ID</dt><dd><code>{certificate.node_id}</code></dd></div><div><dt>Valid from</dt><dd>{time(certificate.not_before_unix_seconds)}</dd></div><div><dt>Valid until</dt><dd>{time(certificate.not_after_unix_seconds)}</dd></div></dl><Status tone={state.tone}>{state.label}</Status>{state.label !== 'Revoked' && hasPermission('certificate.revoke', certificate.network_id) ? <Button variant="danger" onClick={() => void revoke(certificate.network_id, certificate.serial)}><Ban size={16} />Revoke certificate</Button> : null}</div> }) : <p>No certificate records.</p>}</section></>
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
  return <><PageHeader title="Audit events" /><DataTable columns={columns} rows={events} rowKey={(event) => event.event_id} empty={<p>No audit events.</p>} /></>
}
