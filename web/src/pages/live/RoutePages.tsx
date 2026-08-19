import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Clock3, Globe2, Network, Route as RouteIcon, Waypoints } from 'lucide-react'
import { ActionPanel, Button, Callout, ChoiceGroup, Field, FormLayout, FormStack, PageHeader, RecordList, ReviewPanel, SearchField, Status } from '../../components/ui'
import { useControlPlane, type ControllerRoute } from '../../lib/control-plane'
import { isCanonicalIpPrefix } from '../../lib/ip-prefix'
import { ErrorMessage, Missing, VisibilityToolbar, routeState, routeModeDescription, routePurpose, type RecordVisibility } from './shared'

export function RoutesPage() {
  const { inventory, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const records = inventory?.routes ?? []
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const [purpose, setPurpose] = useState<'all' | 'private' | 'exit' | 'review'>('all')
  const [query, setQuery] = useState('')
  const normalizedQuery = query.trim().toLowerCase()
  const visibleRecords = records.filter((route) => {
    const state = routeState(route)
    const purposeMatch = purpose === 'all' || (purpose === 'private' && route.kind === 'subnet') || (purpose === 'exit' && route.kind === 'exit') || (purpose === 'review' && route.state === 'advertised' && state.actionable)
    const queryMatch = !normalizedQuery || [route.prefix, route.node_id, routePurpose(route), inventory?.nodes.find((node) => node.node_id === route.node_id)?.name].some((value) => value?.toLowerCase().includes(normalizedQuery))
    return (visibility === 'all' || state.actionable) && purposeMatch && queryMatch
  })
  const privateRoutes = records.filter((route) => route.kind === 'subnet' && routeState(route).actionable).length
  const exits = records.filter((route) => route.kind === 'exit' && route.state === 'approved' && routeState(route).actionable).length
  const needsReview = records.filter((route) => route.state === 'advertised' && routeState(route).actionable).length
  const purposeOptions = [
    { id: 'all' as const, label: 'All paths', detail: `${records.filter((route) => routeState(route).actionable).length} current`, icon: <Waypoints size={18} /> },
    { id: 'private' as const, label: 'Private destinations', detail: `${privateRoutes} configured`, icon: <Network size={18} /> },
    { id: 'exit' as const, label: 'Internet exits', detail: `${exits} configured`, icon: <Globe2 size={18} /> },
    { id: 'review' as const, label: 'Needs review', detail: needsReview ? `${needsReview} waiting` : 'Nothing waiting', icon: <Clock3 size={18} /> },
  ]
  return <>
    <PageHeader title="Routes" action={networkId && hasPermission('route.manage', networkId) ? <Button to="/routes/new" variant="primary"><RouteIcon size={16} />Add path</Button> : undefined} />
    <nav className="intent-switcher" aria-label="Route views">{purposeOptions.map((option) => <button key={option.id} type="button" aria-pressed={purpose === option.id} onClick={() => setPurpose(option.id)}><span className="intent-switcher__icon" aria-hidden="true">{option.icon}</span><span><strong>{option.label}</strong><small>{option.detail}</small></span></button>)}</nav>
    <div className="guided-list">
      <VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Current only" visible={visibleRecords.length} total={records.length}><SearchField label="Search routes" placeholder="Search destination or node" value={query} onChange={setQuery} /></VisibilityToolbar>
      {visibleRecords.length ? <div className="guided-list__rows">{visibleRecords.map((route) => {
        const node = inventory?.nodes.find((candidate) => candidate.node_id === route.node_id)
        const state = routeState(route)
        return <article className="guided-row" key={route.route_id}>
          <span className={`guided-row__icon ${route.kind === 'exit' ? 'is-exit' : ''}`} aria-hidden="true">{route.kind === 'exit' ? <Globe2 size={19} /> : <RouteIcon size={19} />}</span>
          <div className="guided-row__identity"><small>{routePurpose(route)}</small><strong>{route.kind === 'exit' ? 'Default internet path' : route.prefix}</strong>{route.kind === 'exit' ? <span><code>{route.prefix}</code></span> : null}</div>
          <div className="guided-row__fact"><small>Through</small><strong>{node?.name ?? 'Unknown node'}</strong><span>{routeModeDescription(route.mode)}</span></div>
          <div className="guided-row__fact"><small>Status</small><Status tone={state.tone}>{state.label}</Status><span>{route.state === 'advertised' ? 'Approval required' : `Metric ${route.metric}`}</span></div>
          <Button to={`/routes/${route.route_id}`} variant={route.state === 'advertised' && state.actionable ? 'primary' : 'quiet'}>{route.state === 'advertised' && state.actionable ? 'Review' : 'Details'}</Button>
        </article>
      })}</div> : <div className="guided-list__empty"><RouteIcon aria-hidden="true" /><strong>No paths</strong></div>}
    </div>
  </>
}

export function RouteDetailPage() {
  const { routeId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const route = inventory?.routes.find((candidate) => candidate.route_id === routeId)
  const [error, setError] = useState('')
  if (!route) return <Missing title="Route not found" back="/routes" />
  const activeRoute = route
  const state = routeState(route)
  const canManage = hasPermission('route.manage', route.network_id) && state.actionable
  async function withdraw() { try { await request(`/v1/admin/routes/${activeRoute.route_id}/withdraw`, { method: 'POST' }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Withdrawal failed.') } }
  const node = inventory?.nodes.find((candidate) => candidate.node_id === route.node_id)
  return <><PageHeader title={route.kind === 'exit' ? 'Internet path' : route.prefix} action={<div className="button-row">{canManage && route.state === 'advertised' ? <Button to={`/routes/${route.route_id}/approve`} variant="primary">Approve path</Button> : null}<Button to="/routes">All paths</Button></div>} /><div className="detail-hero"><span className="detail-hero__icon" aria-hidden="true">{route.kind === 'exit' ? <Globe2 /> : <RouteIcon />}</span><div><h2>{route.kind === 'exit' ? 'This network → Internet' : `This network → ${route.prefix}`}</h2></div><Status tone={state.tone}>{state.label}</Status></div><RecordList rows={[["Destination", <code>{route.prefix}</code>], ["Forwarding node", node?.name ?? route.node_id], ["Address handling", routeModeDescription(route.mode)], ["Preference", `Metric ${route.metric}`], ["Route ID", <code>{route.route_id}</code>]]} /><ErrorMessage value={error} />{canManage ? <Button variant="danger" onClick={() => void withdraw()}>Remove path</Button> : null}</>
}

export function CreateRoutePage() {
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const eligibleNodes = (inventory?.nodes ?? []).filter((node) => node.revoked_at_unix_seconds === undefined && node.enrollment_class === 'durable')
  const [purpose, setPurpose] = useState<'private' | 'exit'>('private')
  const [prefix, setPrefix] = useState('')
  const [nodeId, setNodeId] = useState(eligibleNodes[0]?.node_id ?? '')
  const [mode, setMode] = useState('nat')
  const [metric, setMetric] = useState('100')
  const [error, setError] = useState('')
  useEffect(() => { if (!nodeId && eligibleNodes[0]) setNodeId(eligibleNodes[0].node_id) }, [eligibleNodes, nodeId])
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const destination = purpose === 'exit' ? '0.0.0.0/0' : prefix.trim()
    if (!inventory?.network || !destination || !nodeId) return setError('Enter a destination and choose a node.')
    if (!isCanonicalIpPrefix(destination)) return setError('Enter a canonical IPv4 or IPv6 destination prefix.')
    try { const assigned = await request<ControllerRoute>('/v1/admin/routes/assign', { method: 'POST', body: { network_id: inventory.network.network_id, node_id: nodeId, prefix: destination, mode, metric: Number(metric) } }); await refresh(); navigate(`/routes/${assigned.route_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Route assignment failed.') }
  }
  const selectedNode = eligibleNodes.find((node) => node.node_id === nodeId)
  const destination = purpose === 'exit' ? 'Internet (0.0.0.0/0)' : prefix || 'Choose a private prefix'
  return <><PageHeader title="Add traffic path" action={<Button to="/routes" variant="quiet">Cancel</Button>} /><FormLayout form={<FormStack onSubmit={submit}>
    <ChoiceGroup label="Destination" value={purpose} onChange={(value) => setPurpose(value as typeof purpose)} options={[{ value: 'private', label: 'Private destination' }, { value: 'exit', label: 'Internet' }]} />
    {purpose === 'private' ? <Field label="Destination prefix"><input placeholder="10.20.0.0/16" value={prefix} onChange={(event) => setPrefix(event.target.value)} spellCheck={false} /></Field> : <Callout>The selected node becomes the network exit for <code>0.0.0.0/0</code>.</Callout>}
    <ChoiceGroup label="Route through" value={nodeId} onChange={setNodeId} options={eligibleNodes.map((node) => ({ value: node.node_id, label: node.name || 'Unnamed node', description: node.ipv4_address ?? node.ipv6_address ?? 'Durable enrollment' }))} />
    {!eligibleNodes.length ? <Callout tone="warning">Add a durable node before creating a traffic path.</Callout> : null}
    <ChoiceGroup label="Address handling" value={mode} onChange={setMode} options={[{ value: 'nat', label: 'Translate addresses', description: 'Use NAT when the destination has no return route.' }, { value: 'routed', label: 'Preserve source addresses', description: 'Use routed mode when the destination has a return route.' }]} />
    <details className="advanced-settings"><summary>Advanced</summary><Field label="Route preference" hint="Lower values run first."><input type="number" min="0" value={metric} onChange={(event) => setMetric(event.target.value)} /></Field></details>
    <ErrorMessage value={error} /><div className="button-row"><Button type="submit" variant="primary" disabled={!eligibleNodes.length}>Assign route</Button><Button to="/routes">Cancel</Button></div>
  </FormStack>} review={<ReviewPanel title="Review" rows={[["Purpose", purpose === 'exit' ? 'Internet access' : 'Private destination'], ["Destination", <code>{destination}</code>], ["Through", selectedNode?.name ?? 'Choose a node'], ["Address handling", routeModeDescription(mode as ControllerRoute['mode'])]]} />} /></>
}

export function ApproveRoutePage() {
  const { routeId } = useParams()
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const route = inventory?.routes.find((candidate) => candidate.route_id === routeId)
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  if (!route) return <Missing title="Route not found" back="/routes" />
  if (route.state !== 'advertised' || !routeState(route).actionable) return <PageHeader title="Route is not actionable" action={<Button to={`/routes/${route.route_id}`}>View route</Button>} />
  const activeRoute = route
  async function approve() { try { await request(`/v1/admin/routes/${activeRoute.route_id}/approve`, { method: 'POST' }); await refresh(); navigate(`/routes/${activeRoute.route_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Approval failed.') } }
  return <><PageHeader title="Approve route" /><RecordList rows={[["Prefix", <code>{route.prefix}</code>], ["Node ID", <code>{route.node_id}</code>]]} /><ActionPanel><Field label={`Type ${route.prefix} to confirm`}><input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></Field><ErrorMessage value={error} /><Button variant="primary" disabled={confirmation !== route.prefix} onClick={() => void approve()}>Approve route</Button></ActionPanel></>
}
