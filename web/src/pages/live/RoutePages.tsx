import { useEffect, useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ChevronRight, Globe2, Route as RouteIcon } from 'lucide-react'
import { Button, Callout, ChoiceGroup, Field, FormStack, PageHeader, RecordList, ReviewPanel, SearchField, Status } from '../../components/ui'
import { useControlPlane, type ControllerRoute } from '../../lib/control-plane'
import { isCanonicalIpPrefix } from '../../lib/ip-prefix'
import { ErrorMessage, Missing, VisibilityToolbar, routeState, routeModeDescription, routePurpose, type RecordVisibility } from './shared'
import '../traffic-workspace.css'

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
  const visibleScope = records.filter((route) => visibility === 'all' || routeState(route).actionable)
  const purposeOptions = [
    { id: 'all' as const, label: 'All paths', count: visibleScope.length },
    { id: 'private' as const, label: 'Private destinations', count: visibleScope.filter((route) => route.kind === 'subnet').length },
    { id: 'exit' as const, label: 'Internet exits', count: visibleScope.filter((route) => route.kind === 'exit').length },
    { id: 'review' as const, label: 'Needs review', count: visibleScope.filter((route) => route.state === 'advertised' && routeState(route).actionable).length },
  ]
  return <div className="traffic-workspace">
    <PageHeader title="Routes" action={networkId && hasPermission('route.manage', networkId) ? <Button to="/routes/new" variant="primary"><RouteIcon aria-hidden="true" size={16} />Add path</Button> : undefined} />
    <div className="traffic-views" role="group" aria-label="Route views">{purposeOptions.map((option) => (
      <button key={option.id} type="button" aria-pressed={purpose === option.id} onClick={() => setPurpose(option.id)}>{option.label}<small>{option.count}</small></button>
    ))}</div>
    <section className="traffic-list" aria-label="Route inventory">
      <VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Current only" visible={visibleRecords.length} total={records.length}><SearchField label="Search routes" placeholder="Search destination or node" value={query} onChange={setQuery} /></VisibilityToolbar>
      {visibleRecords.length ? <>
        <div className="traffic-list__head" aria-hidden="true"><span>Destination</span><span>Forwarding node</span><span>State</span></div>
        <ul>{visibleRecords.map((route) => {
          const node = inventory?.nodes.find((candidate) => candidate.node_id === route.node_id)
          const state = routeState(route)
          const review = route.state === 'advertised' && state.actionable
          return <li key={route.route_id}><Link className="traffic-row" to={`/routes/${route.route_id}`}>
            <span className="traffic-row__identity">
              {route.kind === 'exit' ? <Globe2 aria-hidden="true" size={16} /> : <RouteIcon aria-hidden="true" size={16} />}
              <span><strong>{route.kind === 'exit' ? 'Default internet path' : <code>{route.prefix}</code>}</strong><small>{route.kind === 'exit' ? <code>{route.prefix}</code> : routePurpose(route)}</small></span>
            </span>
            <span className="traffic-row__fact"><strong>{node?.name ?? 'Unknown node'}</strong><small>{routeModeDescription(route.mode)}</small></span>
            <span className="traffic-row__state"><Status tone={state.tone}>{state.label}</Status>{!review ? <small>Metric {route.metric}</small> : null}</span>
            <span className="traffic-row__end">{review ? 'Review' : 'Details'}<ChevronRight aria-hidden="true" size={15} /></span>
          </Link></li>
        })}</ul>
      </> : <p className="traffic-list__empty">{records.length ? 'No paths match this view.' : 'No paths configured.'}</p>}
    </section>
  </div>
}

export function RouteDetailPage() {
  const { routeId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const route = inventory?.routes.find((candidate) => candidate.route_id === routeId)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  if (!route) return <Missing title="Route not found" back="/routes" />
  const activeRoute = route
  const state = routeState(route)
  const canManage = hasPermission('route.manage', route.network_id) && state.actionable
  async function withdraw() {
    if (pending) return
    setPending(true)
    setError('')
    try {
      await request(`/v1/admin/routes/${activeRoute.route_id}/withdraw`, { method: 'POST' })
      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Withdrawal failed.')
    } finally {
      setPending(false)
    }
  }
  const node = inventory?.nodes.find((candidate) => candidate.node_id === route.node_id)
  return <div className="traffic-workspace">
    <PageHeader title={route.kind === 'exit' ? 'Internet path' : route.prefix} description={routePurpose(route)} action={<div className="button-row">
      <Button to="/routes" variant="quiet">All paths</Button>
      {canManage && route.state === 'advertised' ? <Button to={`/routes/${route.route_id}/approve`} variant="primary">Approve path</Button> : null}
    </div>} />
    <div className="traffic-layout">
      <div className="traffic-content">
        <section aria-labelledby="route-forwarding">
          <h2 className="traffic-section-heading" id="route-forwarding">Forwarding</h2>
          <RecordList rows={[
            ['Destination', <code>{route.prefix}</code>],
            ['Forwarding node', node?.name ?? route.node_id],
            ['Address handling', routeModeDescription(route.mode)],
            ['Preference', `Metric ${route.metric}`],
          ]} />
        </section>
        {canManage ? <section aria-labelledby="remove-path">
          <h2 className="traffic-section-heading" id="remove-path">Remove path</h2>
          <ErrorMessage value={error} />
          <Button variant="danger" disabled={pending} onClick={() => void withdraw()}>{pending ? 'Removing…' : 'Remove path'}</Button>
        </section> : null}
      </div>
      <aside className="traffic-inspector">
        <ReviewPanel title="Route information" rows={[
          ['State', <Status tone={state.tone}>{state.label}</Status>],
          ['Route ID', <code>{route.route_id}</code>],
        ]} />
      </aside>
    </div>
  </div>
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
  const [pending, setPending] = useState(false)
  useEffect(() => { if (!nodeId && eligibleNodes[0]) setNodeId(eligibleNodes[0].node_id) }, [eligibleNodes, nodeId])
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending) return
    const destination = purpose === 'exit' ? '0.0.0.0/0' : prefix.trim()
    if (!inventory?.network || !destination || !nodeId) return setError('Enter a destination and choose a node.')
    if (!isCanonicalIpPrefix(destination)) return setError('Enter a canonical IPv4 or IPv6 destination prefix.')
    setPending(true)
    setError('')
    try {
      const assigned = await request<ControllerRoute>('/v1/admin/routes/assign', {
        method: 'POST',
        body: { network_id: inventory.network.network_id, node_id: nodeId, prefix: destination, mode, metric: Number(metric) },
      })
      await refresh()
      navigate(`/routes/${assigned.route_id}`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Route assignment failed.')
    } finally {
      setPending(false)
    }
  }
  const selectedNode = eligibleNodes.find((node) => node.node_id === nodeId)
  const destination = purpose === 'exit' ? 'Internet (0.0.0.0/0)' : prefix || 'Choose a private prefix'
  return <div className="traffic-workspace">
    <PageHeader title="Add traffic path" />
    <div className="traffic-layout traffic-form">
      <div>
        <FormStack onSubmit={submit}>
          <ChoiceGroup label="Destination" value={purpose} onChange={(value) => setPurpose(value as typeof purpose)} options={[{ value: 'private', label: 'Private destination' }, { value: 'exit', label: 'Internet' }]} />
          {purpose === 'private' ? <Field label="Destination prefix"><input placeholder="10.20.0.0/16" value={prefix} onChange={(event) => setPrefix(event.target.value)} spellCheck={false} /></Field> : <Callout>The selected node becomes the network exit for <code>0.0.0.0/0</code>.</Callout>}
          <Field label="Route through">
            <select value={nodeId} onChange={(event) => setNodeId(event.target.value)}>
              {!eligibleNodes.length ? <option value="">No eligible durable nodes</option> : null}
              {eligibleNodes.map((node) => <option key={node.node_id} value={node.node_id}>{node.name || 'Unnamed node'}{node.ipv4_address || node.ipv6_address ? ` · ${node.ipv4_address ?? node.ipv6_address}` : ''}</option>)}
            </select>
          </Field>
          {!eligibleNodes.length ? <Callout tone="warning">Add a durable node before creating a traffic path.</Callout> : null}
          <ChoiceGroup label="Address handling" value={mode} onChange={setMode} options={[
            { value: 'nat', label: 'Translate addresses', description: 'Use NAT when the destination has no return route.' },
            { value: 'routed', label: 'Preserve source addresses', description: 'Use routed mode when the destination has a return route.' },
          ]} />
          <details className="advanced-settings"><summary>Route preference</summary><Field label="Metric" hint="Lower values run first."><input type="number" min="0" value={metric} onChange={(event) => setMetric(event.target.value)} /></Field></details>
          <ErrorMessage value={error} />
          <div className="button-row"><Button type="submit" variant="primary" disabled={pending || !eligibleNodes.length}>{pending ? 'Assigning…' : 'Assign route'}</Button><Button to="/routes" variant="quiet">Cancel</Button></div>
        </FormStack>
      </div>
      <aside><ReviewPanel title="Path preview" rows={[
        ['Purpose', purpose === 'exit' ? 'Internet access' : 'Private destination'],
        ['Destination', <code>{destination}</code>],
        ['Through', selectedNode?.name ?? 'Choose a node'],
        ['Address handling', routeModeDescription(mode as ControllerRoute['mode'])],
        ['Preference', metric],
      ]} /></aside>
    </div>
  </div>
}

export function ApproveRoutePage() {
  const { routeId } = useParams()
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const route = inventory?.routes.find((candidate) => candidate.route_id === routeId)
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  if (!route) return <Missing title="Route not found" back="/routes" />
  if (route.state !== 'advertised' || !routeState(route).actionable) return <PageHeader title="Route is not actionable" action={<Button to={`/routes/${route.route_id}`}>View route</Button>} />
  const activeRoute = route
  async function approve() {
    if (pending) return
    setPending(true)
    setError('')
    try {
      await request(`/v1/admin/routes/${activeRoute.route_id}/approve`, { method: 'POST' })
      await refresh()
      navigate(`/routes/${activeRoute.route_id}`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Approval failed.')
    } finally {
      setPending(false)
    }
  }
  const node = inventory?.nodes.find((candidate) => candidate.node_id === route.node_id)
  return <div className="traffic-workspace">
    <PageHeader title="Approve route" description={route.prefix} />
    <div className="traffic-layout">
      <section className="traffic-content" aria-labelledby="authorize-route">
        <h2 className="traffic-section-heading" id="authorize-route">Approval</h2>
        <Callout tone="warning">Approval distributes this route in the next configuration epoch. Access rules still apply.</Callout>
        <FormStack onSubmit={(event) => {
          event.preventDefault()
          if (confirmation === route.prefix) void approve()
        }}>
          <Field label={`Type ${route.prefix} to confirm`}><input value={confirmation} onChange={(event) => setConfirmation(event.target.value)} spellCheck={false} autoComplete="off" /></Field>
          <ErrorMessage value={error} />
          <div className="button-row"><Button variant="primary" type="submit" disabled={pending || confirmation !== route.prefix}>{pending ? 'Approving…' : 'Approve route'}</Button><Button to={`/routes/${route.route_id}`} variant="quiet">Cancel</Button></div>
        </FormStack>
      </section>
      <aside className="traffic-inspector"><ReviewPanel title="Advertisement" rows={[
        ['Destination', <code>{route.prefix}</code>],
        ['Forwarding node', node?.name ?? <code>{route.node_id}</code>],
        ['Address handling', routeModeDescription(route.mode)],
        ['Preference', `Metric ${route.metric}`],
        ['State', <Status tone="warning">{routeState(route).label}</Status>],
      ]} /></aside>
    </div>
  </div>
}
