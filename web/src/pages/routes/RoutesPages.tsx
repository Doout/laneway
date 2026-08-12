import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { CheckCircle2, CircleSlash2, MapPinned, Route as RouteIcon, Server, ShieldAlert, Waypoints } from 'lucide-react'
import { useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import {
  Button,
  Callout,
  ChoiceGroup,
  DataTable,
  DetailLayout,
  EmptyState,
  EntityTitle,
  Field,
  FilterSelect,
  FlowPath,
  FormLayout,
  FormStack,
  IdentityBlock,
  PageHeader,
  ReviewPanel,
  Section,
  SearchField,
  Status,
  Toolbar,
} from '../../components/ui'
import { type RouteRecord } from '../../lib/demo-data'
import { useControlPlane, type ControllerNode, type ControllerRoute } from '../../lib/control-plane'
import { isCanonicalIpPrefix } from '../../lib/ip-prefix'
import { controllerRoutes, isPendingControllerRoute } from '../../lib/live-records'
import { attributed, persistedRoutes, readDemoState, updateDemoState } from '../../lib/persisted-demo-state'
import './routes-pages.css'

type RouteFormState = {
  name: string
  destination: string
  kind: 'subnet' | 'exit'
  via: string
  mode: 'NAT' | 'Routed'
  metric: string
  lifetime: string
  confirmed: boolean
}

type RouteFormErrors = Partial<Record<keyof RouteFormState, string>>

const initialRoute: RouteFormState = {
  name: '',
  destination: '10.24.0.0/16',
  kind: 'subnet',
  via: 'atlas-gateway',
  mode: 'NAT',
  metric: '100',
  lifetime: 'No expiry',
  confirmed: false,
}

function routeForId(id?: string, records = persistedRoutes()) {
  return records.find(route => route.id === id || route.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') === id)
}

function formatControllerTime(timestamp?: number) {
  if (timestamp === undefined) return 'Unavailable'
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(timestamp * 1000))
}

function controllerRouteMode(route?: ControllerRoute) {
  if (!route) return 'Unavailable'
  if (route.mode === 'nat') return 'NAT'
  if (route.mode === 'routed') return 'Routed'
  return 'None'
}

function controllerRouteKind(route?: ControllerRoute) {
  if (!route) return 'Unavailable'
  return route.kind.charAt(0).toUpperCase() + route.kind.slice(1)
}

function canReceiveSubnetRoute(node: ControllerNode) {
  const leaseActive = node.lease_expires_at_unix_seconds === undefined || node.lease_expires_at_unix_seconds > Math.floor(Date.now() / 1000)
  return node.enrollment_class === 'durable' && node.revoked_at_unix_seconds === undefined && leaseActive
}

function RouteNotFound({ id }: { id?: string }) {
  return <EmptyState icon={<RouteIcon />} title="Route not found" description={`No route matches ${id ? `“${id}”` : 'this address'}.`} action={<Button to="/routes" variant="primary">Return to routes</Button>} />
}

export function RoutesListPage() {
  const { live, inventory } = useControlPlane()
  const records = live ? controllerRoutes(inventory?.routes ?? [], inventory?.nodes ?? []) : persistedRoutes()
  const [searchParams, setSearchParams] = useSearchParams()
  const [query, setQuery] = useState('')
  const approvedState = live ? 'Approved' : 'Healthy'
  const stateFromQuery = searchParams.get('state') === 'pending'
    ? 'Pending approval'
    : searchParams.get('state') === 'approved' ? approvedState : 'all'
  const [state, setState] = useState(stateFromQuery)
  const [mode, setMode] = useState('all')
  const [selectedId, setSelectedId] = useState(records.find(route => route.state === 'Pending approval')?.id ?? records[0]?.id ?? '')

  useEffect(() => {
    const requestedState = searchParams.get('state')
    setState(requestedState === 'pending' ? 'Pending approval' : requestedState === 'approved' ? approvedState : 'all')
  }, [approvedState, searchParams])

  function changeState(value: string) {
    setState(value)
    setSearchParams(current => {
      const next = new URLSearchParams(current)
      if (value === 'Pending approval') next.set('state', 'pending')
      else if (value === approvedState) next.set('state', 'approved')
      else next.delete('state')
      return next
    }, { replace: true })
  }

  const visibleRoutes = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return records.filter(route => {
      const matchesQuery = !normalized || [route.name, route.destination, route.via].some(value => value.toLowerCase().includes(normalized))
      const matchesState = state === 'all' || route.state === state
      const routeMode = live ? controllerRouteMode(inventory?.routes.find(record => record.route_id === route.id)) : route.mode
      const matchesMode = mode === 'all' || routeMode === mode
      return matchesQuery && matchesState && matchesMode
    })
  }, [inventory?.routes, live, mode, query, records, state])
  const selected = visibleRoutes.find(route => route.id === selectedId) ?? visibleRoutes[0]
  const selectedControllerRoute = live ? inventory?.routes.find(route => route.route_id === selected?.id) : undefined
  const pendingCount = records.filter(route => route.state === 'Pending approval').length
  const approvedCount = records.filter(route => route.state === approvedState).length
  const thirdSummaryCount = live ? inventory?.routes.filter(route => route.state === 'withdrawn').length ?? 0 : records.filter(route => route.state === 'Relay fallback').length

  return <div className="routes-page">
    <PageHeader
      title="Routes"
      action={<Button variant="primary" to="/routes/new"><RouteIcon aria-hidden="true" size={17} />Create route</Button>}
    />
    <div className="routes-health-strip" aria-label="Route inventory summary"><div><strong>{approvedCount}</strong><span>{live ? 'Approved routes' : 'Healthy routes'}</span></div><div><strong>{pendingCount}</strong><span>Approval queue</span></div><div><strong>{thirdSummaryCount}</strong><span>{live ? 'Withdrawn routes' : 'Relay fallback'}</span></div><div><strong>{live ? inventory?.network?.configuration_epoch ?? '—' : 418}</strong><span>Configuration epoch</span></div></div>
    <Toolbar filters={<>
      <div className="routes-segments" aria-label="Route state"><button className={state === 'all' ? 'is-active' : ''} onClick={() => changeState('all')}>All</button><button className={state === approvedState ? 'is-active' : ''} onClick={() => changeState(approvedState)}>{live ? 'Approved' : 'Healthy'}</button><button className={state === 'Pending approval' ? 'is-active' : ''} onClick={() => changeState('Pending approval')}>Needs attention</button></div>
      <FilterSelect label="Filter by mode" value={mode} onChange={setMode}>
        <option value="all">All modes</option>
        <option value="NAT">NAT</option>
        <option value="Routed">Routed</option>
        {live ? <option value="None">None</option> : null}
      </FilterSelect>
      <span className="routes-count" aria-live="polite">{visibleRoutes.length} shown</span>
    </>}>
      <SearchField label="Search routes" placeholder="Search name, prefix, or next hop" value={query} onChange={setQuery} />
    </Toolbar>
    <div className="routes-workspace"><section className="routes-panel routes-inventory"><DataTable
        rows={visibleRoutes}
        rowKey={route => route.id}
        columns={[
          { key: 'route', label: 'Route', render: route => <EntityTitle icon={<MapPinned size={16} />} subtitle={route.id}>{route.name}</EntityTitle> },
          { key: 'destination', label: 'Destination', render: route => <code>{route.destination}</code> },
          { key: 'via', label: 'Gateway', render: route => route.via },
          { key: 'mode', label: 'Mode', render: route => live ? controllerRouteMode(inventory?.routes.find(record => record.route_id === route.id)) : route.mode },
          { key: 'status', label: 'State', render: route => <Status tone={route.tone}>{route.state}</Status> },
          { key: 'actions', label: '', align: 'end', render: route => <Button variant={selected?.id === route.id ? 'secondary' : 'quiet'} onClick={() => setSelectedId(route.id)}>Inspect</Button> },
        ]}
        empty={<div className="routes-empty"><RouteIcon aria-hidden="true" /><h2>No routes match</h2><p>Clear a filter or search for a different prefix.</p></div>}
      /></section>{selected ? <aside className="routes-panel routes-inspector"><span className="routes-panel-label">Inspector</span><h2>{selected.name}</h2><p><code>{selected.destination}</code> · {selected.state}</p><dl><div><dt>Gateway</dt><dd>{selected.via}</dd></div><div><dt>Mode</dt><dd>{live ? controllerRouteMode(selectedControllerRoute) : selected.mode}</dd></div><div><dt>Metric</dt><dd>{selected.metric}</dd></div><div><dt>{live ? 'Created' : 'Requested'}</dt><dd>{live ? formatControllerTime(selectedControllerRoute?.created_at_unix_seconds) : selected.state === 'Pending approval' ? '14 minutes ago' : 'Today, 09:38'}</dd></div></dl><div className="button-row">{selected.state === 'Pending approval' ? <Button variant="primary" to={`/routes/${selected.id}/approve`}>Review request</Button> : <Button variant="primary" to={`/routes/${selected.id}`}>View route</Button>}</div></aside> : null}</div>
  </div>
}

export function CreateRoutePage() {
  const { live, inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const eligibleNodes = live ? inventory?.nodes.filter(canReceiveSubnetRoute) ?? [] : []
  const firstEligibleNodeId = eligibleNodes[0]?.node_id
  const [form, setForm] = useState<RouteFormState>(() => ({
    ...initialRoute,
    destination: live ? '' : initialRoute.destination,
    via: live ? firstEligibleNodeId ?? '' : initialRoute.via,
  }))
  const [errors, setErrors] = useState<RouteFormErrors>({})
  const [submitError, setSubmitError] = useState('')
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (live && !form.via && firstEligibleNodeId) {
      setForm(current => ({ ...current, via: firstEligibleNodeId }))
    }
  }, [firstEligibleNodeId, form.via, live])

  function update<K extends keyof RouteFormState>(key: K, value: RouteFormState[K]) {
    setForm(current => ({ ...current, [key]: value }))
    setErrors(current => ({ ...current, [key]: undefined }))
  }

  function validate() {
    const next: RouteFormErrors = {}
    if (!live && form.name.trim().length < 3) next.name = 'Enter a route name with at least 3 characters.'
    if (!isCanonicalIpPrefix(form.destination)) next.destination = 'Enter a canonical IPv4 or IPv6 CIDR prefix.'
    if (form.kind === 'exit' && !['0.0.0.0/0', '::/0'].includes(form.destination.trim())) next.destination = 'Exit routes must use 0.0.0.0/0 or ::/0.'
    if (form.kind === 'subnet' && ['0.0.0.0/0', '::/0'].includes(form.destination.trim())) next.destination = 'A default prefix must be created as an exit route.'
    const metric = Number(form.metric)
    if (!Number.isInteger(metric) || metric < 0 || metric > 1_000_000) next.metric = 'Metric must be a whole number from 0 to 1,000,000.'
    if (!form.confirmed) next.confirmed = 'Confirm the forwarding impact before continuing.'
    setErrors(next)
    return Object.keys(next).length === 0
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!validate()) return
    const draft: RouteRecord = {
      id: 'rte_preview',
      name: form.name.trim(),
      destination: form.destination.trim(),
      via: form.via,
      mode: form.mode,
      metric: Number(form.metric),
      state: 'Pending approval',
      tone: 'warning',
    }
    if (live) {
      if (!inventory?.network || !form.via) {
        setSubmitError('Choose a controller network and forwarding node before creating this route.')
        return
      }
      setPending(true)
      setSubmitError('')
      try {
        const created = await request<ControllerRoute>('/v1/admin/routes/assign', { method: 'POST', body: {
          network_id: inventory.network.network_id,
          node_id: form.via,
          prefix: form.destination.trim(),
          mode: form.mode.toLowerCase(),
          metric: Number(form.metric),
        } })
        await refresh()
        navigate(`/routes/${created.route_id}`)
      } catch (error) {
        setSubmitError(error instanceof Error ? error.message : 'The controller could not assign this route.')
      } finally {
        setPending(false)
      }
      return
    }
    updateDemoState(current => ({ ...current, routes: { ...current.routes, [draft.id]: { ...attributed('Route advertisement created; awaiting approval'), record: draft } } }))
    navigate('/routes/rte_preview/approve', { state: { route: draft, lifetime: form.lifetime, kind: form.kind } })
  }

  return <div className="routes-page routes-form-page">
    <PageHeader title="Create route" action={<Button variant="quiet" to="/routes">Cancel</Button>} />
    <FormLayout
      form={<FormStack onSubmit={submit}>
        {!live ? <Field label="Route name" error={errors.name}>
          <input aria-invalid={Boolean(errors.name)} value={form.name} onChange={event => update('name', event.target.value)} placeholder="Production services" autoFocus />
        </Field> : null}
        <Field label="Destination prefix" hint="Use a canonical CIDR prefix, such as 10.24.0.0/16." error={errors.destination}>
          <input aria-invalid={Boolean(errors.destination)} value={form.destination} onChange={event => update('destination', event.target.value)} spellCheck={false} autoFocus={live} />
        </Field>
        {live ? <Field label="Route kind"><input value="Subnet" readOnly /></Field> : <ChoiceGroup label="Route kind" value={form.kind} onChange={value => update('kind', value as RouteFormState['kind'])} options={[
          { value: 'subnet', label: 'Subnet', description: 'Private network behind a Connector.' },
          { value: 'exit', label: 'Exit', description: 'Default traffic through an exit node.' },
        ]} />}
        <Field label="Via node" hint={live ? 'Assignment grants subnet-router capability to the selected durable node.' : 'The node must have the matching Connector or exit capability.'}>
          <select value={form.via} onChange={event => update('via', event.target.value)}>{live ? <>{!eligibleNodes.length ? <option value="">No eligible durable nodes</option> : null}{eligibleNodes.map(node => <option key={node.node_id} value={node.node_id}>{node.name || node.node_id}</option>)}</> : <><option value="atlas-gateway">atlas-gateway · Connector</option><option value="home-pi">home-pi · Connector</option><option value="fra-exit-01">fra-exit-01 · Exit node</option></>}</select>
        </Field>
        <ChoiceGroup label="Forwarding mode" value={form.mode} onChange={value => update('mode', value as RouteFormState['mode'])} options={[
          { value: 'NAT', label: 'NAT', description: 'Translate overlay sources at the forwarding node.' },
          { value: 'Routed', label: 'Routed', description: 'Preserve source addresses; the destination needs a return route.' },
        ]} />
        <div className="routes-field-grid">
          <Field label="Metric" hint="Lower metrics win for equal prefixes." error={errors.metric}>
            <input type="number" min="0" max="1000000" step="1" aria-invalid={Boolean(errors.metric)} value={form.metric} onChange={event => update('metric', event.target.value)} />
          </Field>
          {!live ? <Field label="Lifetime" hint="Expired advertisements are withdrawn automatically.">
            <select value={form.lifetime} onChange={event => update('lifetime', event.target.value)}>
              <option>No expiry</option>
              <option>8 hours</option>
              <option>24 hours</option>
              <option>7 days</option>
            </select>
          </Field> : null}
        </div>
        <Callout tone="warning"><strong>Forwarding impact</strong><br />{live ? 'The controller approves this route immediately and includes it in the next configuration epoch.' : `After approval, matching traffic can leave enrolled nodes through ${form.via}.`} Access rules still apply.</Callout>
        <label className="routes-confirm">
          <input type="checkbox" checked={form.confirmed} onChange={event => update('confirmed', event.target.checked)} />
          <span>{live ? 'I understand this assignment grants subnet-router capability and approves the route.' : 'I understand this advertisement changes a network path and requires separate approval.'}</span>
        </label>
        {errors.confirmed ? <p className="routes-error" role="alert">{errors.confirmed}</p> : null}
        {submitError ? <Callout tone="danger">{submitError}</Callout> : null}
        <div className="button-row"><Button type="submit" variant="primary" disabled={pending || (live && !eligibleNodes.length)}>{pending ? 'Assigning…' : live ? 'Assign route' : 'Continue to approval'}</Button><Button variant="quiet" to="/routes">Cancel</Button></div>
      </FormStack>}
      review={<ReviewPanel title="Route preview" rows={[
        ['Destination', <code>{form.destination || '—'}</code>],
        ['Kind', form.kind === 'subnet' ? 'Subnet' : 'Exit'],
        ['Via', form.via],
        ['Mode', form.mode],
        ['Metric', form.metric || '—'],
        ...(live ? [] : [['Lifetime', form.lifetime] as [string, ReactNode]]),
        ['Initial state', <Status tone={live ? 'positive' : 'warning'}>{live ? 'Approved' : 'Advertised'}</Status>],
      ]} />}
    />
  </div>
}

type ApprovalLocation = { route?: RouteRecord; lifetime?: string; kind?: 'subnet' | 'exit' }

export function RouteApprovalPage() {
  const { live, inventory, request, refresh } = useControlPlane()
  const { routeId } = useParams()
  const location = useLocation()
  const navigate = useNavigate()
  const supplied = (location.state as ApprovalLocation | null)?.route
  const liveRecords = controllerRoutes(inventory?.routes ?? [], inventory?.nodes ?? [])
  const route = live ? routeForId(routeId, liveRecords) : (supplied && !readDemoState().routes[supplied.id] ? supplied : undefined) ?? routeForId(routeId)
  const liveRoute = live ? inventory?.routes.find(record => record.route_id === route?.id) : undefined
  const [confirmed, setConfirmed] = useState(false)
  const [confirmation, setConfirmation] = useState('')
  const [decision, setDecision] = useState<'pending' | 'approved' | 'rejected'>('pending')
  const [reason, setReason] = useState('')
  const [error, setError] = useState('')
  const [actionPending, setActionPending] = useState(false)

  if (!route) return <RouteNotFound id={routeId} />
  const activeRoute: RouteRecord = route
  const expected = activeRoute.destination

  async function approve() {
    if (actionPending) return
    if (live && (!liveRoute || !isPendingControllerRoute(liveRoute))) {
      setError('This route no longer has an approval pending.')
      return
    }
    if (!confirmed) {
      setError('Confirm the route details before approving this advertisement.')
      return
    }
    if (confirmation !== expected) {
      setError(`Type ${expected} exactly to approve distribution of this path.`)
      return
    }
    setError('')
    if (live) {
      setActionPending(true)
      try {
        await request(`/v1/admin/routes/${activeRoute.id}/approve`, { method: 'POST' })
        await refresh()
        setDecision('approved')
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : 'The controller could not approve this route.')
      } finally {
        setActionPending(false)
      }
      return
    }
    const record: RouteRecord = { ...activeRoute, state: 'Healthy', tone: 'positive' }
    updateDemoState(current => ({ ...current, routes: { ...current.routes, [activeRoute.id]: { ...attributed('Route approved for distribution'), record } } }))
    setDecision('approved')
  }

  function reject() {
    if (actionPending) return
    if (live) {
      setError('The controller does not expose an administrator route-rejection endpoint. Leave this request pending or reject it from the advertising node.')
      return
    }
    if (reason.trim().length < 8) {
      setError('Add a rejection reason with at least 8 characters for the audit event.')
      return
    }
    if (confirmation !== expected) {
      setError(`Type ${expected} exactly to reject this advertisement.`)
      return
    }
    setError('')
    const record: RouteRecord = { ...activeRoute, state: 'Rejected', tone: 'danger' }
    updateDemoState(current => ({ ...current, routes: { ...current.routes, [activeRoute.id]: { ...attributed(`Route rejected: ${reason.trim()}`), record } } }))
    setDecision('rejected')
  }

  if (decision !== 'pending') {
    const approved = decision === 'approved'
    const decidedRoute: RouteRecord = { ...route, state: approved ? 'Healthy' : 'Rejected', tone: approved ? 'positive' : 'danger' }
    return <div className="routes-page routes-decision" role="status">
      <span className={`routes-decision__icon routes-decision__icon--${decision}`}>{approved ? <CheckCircle2 aria-hidden="true" /> : <CircleSlash2 aria-hidden="true" />}</span>
      <h1>Route {decision}</h1>
      <p>{route.destination} {approved ? 'approved.' : 'rejected.'}</p>
      <div className="button-row"><Button variant="primary" onClick={() => navigate(`/routes/${route.id}`, { state: { route: decidedRoute } })}>View route</Button><Button variant="quiet" to="/routes">All routes</Button></div>
    </div>
  }

  if ((live && (!liveRoute || !isPendingControllerRoute(liveRoute))) || (!live && route.state !== 'Pending approval')) {
    const saved = live ? undefined : readDemoState().routes[route.id]
    return <div className="routes-page routes-decision" role="status">
      <span className="routes-decision__icon routes-decision__icon--approved"><CheckCircle2 aria-hidden="true" /></span>
      <h1>No approval pending</h1>
      <p>{live ? 'This route has no approval awaiting review.' : `${route.name} is ${route.state.toLowerCase()}.${saved ? ` ${saved.result}.` : ''}`}</p>
      <div className="button-row"><Button variant="primary" to={`/routes/${route.id}`}>View route</Button><Button variant="quiet" to="/routes">All routes</Button></div>
    </div>
  }

  return <div className="routes-page routes-approval-page">
    <PageHeader title={`Review ${route.name}`} action={<Button variant="quiet" disabled={actionPending} onClick={() => navigate('/routes')}>Back to approval queue</Button>} />
    <div className="routes-approval-grid">
      <section className="routes-approval-summary">
        <Status tone="warning">Awaiting approval</Status>
        <h2>{route.name}</h2>
        <code className="routes-prefix">{route.destination}</code>
        {!live ? <FlowPath items={[
          <span key="source">Authorized source node</span>,
          <span key="overlay">Laneway overlay</span>,
          <span key="via"><strong>{route.via}</strong><small>{route.mode} forwarding</small></span>,
          <span key="destination"><strong>{route.destination}</strong><small>Private destination</small></span>,
        ]} /> : null}
        <Callout tone="warning"><strong>{live ? 'Approval includes this route in the next configuration epoch.' : 'Approval distributes this route to enrolled nodes.'}</strong><br />ACL rules still apply.</Callout>
      </section>
      <aside className="routes-approval-actions">
        <ReviewPanel title="Advertisement" rows={[
          ['Route ID', <code>{route.id}</code>],
          ['Via node', route.via],
          ['Mode', live ? controllerRouteMode(liveRoute) : route.mode],
          ['Metric', route.metric],
          ['Kind', live ? controllerRouteKind(liveRoute) : (location.state as ApprovalLocation | null)?.kind ?? (route.destination.endsWith('/0') ? 'Exit' : 'Subnet')],
          ['Lifetime', live ? liveRoute ? liveRoute.valid_until_unix_seconds === undefined ? 'No expiry' : formatControllerTime(liveRoute.valid_until_unix_seconds) : 'Unavailable' : (location.state as ApprovalLocation | null)?.lifetime ?? 'No expiry'],
        ]} />
        <label className="routes-confirm">
          <input type="checkbox" checked={confirmed} disabled={actionPending} onChange={event => { setConfirmed(event.target.checked); setError('') }} />
          <span>I verified the destination, forwarding node, mode, and metric.</span>
        </label>
        <Field label={`Type ${expected} to confirm`}>
          <input value={confirmation} disabled={actionPending} onChange={event => { setConfirmation(event.target.value); setError('') }} autoComplete="off" spellCheck={false} />
        </Field>
        {!live ? <Field label="Rejection reason" hint="Required when rejecting.">
          <textarea value={reason} disabled={actionPending} onChange={event => { setReason(event.target.value); setError('') }} placeholder="Explain why this advertisement must not be distributed" />
        </Field> : null}
        {error ? <p className="routes-error" role="alert">{error}</p> : null}
        <div className="button-row"><Button variant="primary" disabled={actionPending || !confirmed || confirmation !== expected} onClick={approve}>{actionPending ? 'Approving…' : 'Approve route'}</Button>{!live ? <Button variant="danger" disabled={actionPending || confirmation !== expected} onClick={reject}>Reject advertisement</Button> : null}<Button variant="quiet" disabled={actionPending} onClick={() => navigate(`/routes/${route.id}`)}>Cancel</Button></div>
      </aside>
    </div>
  </div>
}

export function RouteDetailPage() {
  const { live, inventory, request, refresh } = useControlPlane()
  const { routeId } = useParams()
  const location = useLocation()
  const supplied = (location.state as ApprovalLocation | null)?.route
  const [, setRevision] = useState(0)
  const [showWithdraw, setShowWithdraw] = useState(false)
  const [confirmation, setConfirmation] = useState('')
  const [withdrawError, setWithdrawError] = useState('')
  const [withdrawPending, setWithdrawPending] = useState(false)
  const liveRecords = controllerRoutes(inventory?.routes ?? [], inventory?.nodes ?? [])
  const route = live ? routeForId(routeId, liveRecords) : (supplied && !readDemoState().routes[supplied.id] ? supplied : undefined) ?? routeForId(routeId)
  if (!route) return <RouteNotFound id={routeId} />
  const activeRoute: RouteRecord = route
  const liveRoute = live ? inventory?.routes.find(record => record.route_id === route.id) : undefined
  const saved = live ? undefined : readDemoState().routes[route.id]
  const pending = route.state === 'Pending approval'
  const withdrawn = route.state === 'Withdrawn'
  const liveRouteActive = liveRoute?.state === 'approved' && (liveRoute.valid_until_unix_seconds === undefined || liveRoute.valid_until_unix_seconds > Math.floor(Date.now() / 1000))
  const liveNetworkName = inventory?.network?.name || liveRoute?.network_id || 'Unavailable'
  const forwardingNodeId = liveRoute?.node_id ?? route.via

  async function withdraw(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (withdrawPending) return
    if (confirmation !== activeRoute.destination) {
      setWithdrawError(`Type ${activeRoute.destination} exactly to withdraw this network path.`)
      return
    }
    if (live) {
      setWithdrawPending(true)
      try {
        await request(`/v1/admin/routes/${activeRoute.id}/withdraw`, { method: 'POST' })
        await refresh()
        setShowWithdraw(false)
        setConfirmation('')
        setRevision(value => value + 1)
      } catch (requestError) {
        setWithdrawError(requestError instanceof Error ? requestError.message : 'The controller could not withdraw this route.')
      } finally {
        setWithdrawPending(false)
      }
      return
    }
    const record: RouteRecord = { ...activeRoute, state: 'Withdrawn', tone: 'muted' }
    updateDemoState(current => ({ ...current, routes: { ...current.routes, [activeRoute.id]: { ...attributed('Route withdrawn from distribution'), record } } }))
    setShowWithdraw(false)
    setConfirmation('')
    setRevision(value => value + 1)
  }

  return <div className="routes-page routes-detail-page">
    <PageHeader title={route.name} action={<div className="button-row">{pending ? <Button variant="primary" to={`/routes/${route.id}/approve`}>Review approval</Button> : null}<Button variant="quiet" to="/routes">All routes</Button></div>} />
    <DetailLayout
      identity={<IdentityBlock
        icon={<Waypoints aria-hidden="true" size={34} />}
        title={route.destination}
        state={<Status tone={route.tone}>{route.state}</Status>}
        metadata={[
          ['Route ID', <code>{route.id}</code>],
          ['Kind', live ? controllerRouteKind(liveRoute) : route.destination.endsWith('/0') ? 'Exit' : 'Subnet'],
          ['Mode', live ? controllerRouteMode(liveRoute) : route.mode],
          ['Metric', route.metric],
          ['Network', live ? liveNetworkName : 'Production'],
        ]}
      />}
    >
      {!live ? <Section title="Effective path">
        <FlowPath items={[
          <span key="source"><strong>Enrolled node</strong><small>Authenticated identity</small></span>,
          <span key="policy"><strong>ACL evaluation</strong><small>Fail closed</small></span>,
          <span key="via"><strong>{route.via}</strong><small>{route.mode} forwarding</small></span>,
          <span key="destination"><strong>{route.destination}</strong><small>Destination prefix</small></span>,
        ]} />
        {route.state === 'Relay fallback' ? <Callout tone="warning">Direct QUIC failed; traffic is using an authenticated relay.</Callout> : null}
      </Section> : null}
      <Section title="Forwarding node">
        <div className="routes-node-row"><EntityTitle icon={<Server size={16} />} subtitle={live ? <code>{forwardingNodeId}</code> : 'Connector · Connected'}>{route.via}</EntityTitle><Button variant="quiet" to={`/nodes/${forwardingNodeId}`}>View node</Button></div>
      </Section>
      <Section title="Approval and lifetime">
        <dl className="routes-detail-list">
          <div><dt>{live ? 'Created' : 'Advertised'}</dt><dd>{live ? formatControllerTime(liveRoute?.created_at_unix_seconds) : 'Today, 09:38 UTC'}</dd></div>
          <div><dt>Approved</dt><dd>{live ? liveRoute?.approved_at_unix_seconds === undefined ? 'Not approved' : formatControllerTime(liveRoute.approved_at_unix_seconds) : pending ? 'Not yet approved' : 'Today, 09:42 UTC by operator'}</dd></div>
          <div><dt>Valid until</dt><dd>{live ? liveRoute ? liveRoute.valid_until_unix_seconds === undefined ? 'No expiry' : formatControllerTime(liveRoute.valid_until_unix_seconds) : 'Unavailable' : 'No expiry'}</dd></div>
          <div><dt>Configuration epoch</dt><dd>{live ? inventory?.network?.configuration_epoch ?? 'Unavailable' : pending ? 'Pending' : '418'}</dd></div>
        </dl>
      </Section>
      {saved?.result ? <Callout tone={withdrawn ? 'danger' : 'neutral'}>{saved.result} by {saved.actedBy} · {saved.actedAt}.</Callout> : null}
      <Section title="Withdraw route">
        {withdrawn ? <Callout>This route is no longer distributed.</Callout> : <>
          <Callout tone="danger"><ShieldAlert aria-hidden="true" size={16} /> {live ? liveRouteActive ? `The route is removed in the next configuration epoch. Connections using ${route.destination} may be interrupted when nodes apply that configuration.` : liveRoute?.state === 'advertised' ? 'The advertisement is marked withdrawn and can no longer be approved.' : 'The route is marked withdrawn in the controller.' : `Enrolled nodes will stop receiving ${route.destination}; active connections using this path may be interrupted.`}</Callout>
          {showWithdraw ? <form className="routes-withdraw-form" onSubmit={withdraw}>
            <Field label={`Type ${route.destination} to confirm`} error={withdrawError || undefined}><input value={confirmation} disabled={withdrawPending} onChange={event => { setConfirmation(event.target.value); setWithdrawError('') }} autoComplete="off" spellCheck={false} /></Field>
            <div className="button-row"><Button type="submit" variant="danger" disabled={withdrawPending || confirmation !== route.destination}>{withdrawPending ? 'Withdrawing…' : 'Withdraw route'}</Button><Button variant="quiet" disabled={withdrawPending} onClick={() => { setShowWithdraw(false); setConfirmation(''); setWithdrawError('') }}>Cancel</Button></div>
          </form> : <div className="routes-section-action"><Button variant="danger" onClick={() => setShowWithdraw(true)}>Withdraw route</Button></div>}
        </>}
      </Section>
    </DetailLayout>
  </div>
}
