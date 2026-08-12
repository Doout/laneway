import { useState, type FormEvent } from 'react'
import { CircleGauge, Clock3, Network, Plus, RadioTower, ServerCog, ShieldCheck, TriangleAlert } from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'
import { Button, DataTable, EntityTitle, Field, FormStack, PageHeader, Section, Status, type DataColumn } from '../../components/ui'
import {
  addInfrastructureNetwork,
  type InfrastructureNetwork,
} from '../../lib/infrastructure-state'
import { isCanonicalIpPrefix } from '../../lib/ip-prefix'
import { isPendingControllerRoute } from '../../lib/live-records'
import { useInfrastructureView } from './useInfrastructureView'
import './infrastructure.css'

export function InfrastructurePage() {
  const { networks, relays, live, inventory, request, refresh, inventoryPending, inventoryError } = useInfrastructureView()
  const location = useLocation()
  const [creatingNetwork, setCreatingNetwork] = useState(false)
  const [networkName, setNetworkName] = useState('')
  const [addressPool, setAddressPool] = useState(live ? '' : '100.88.3.0/24')
  const [submitted, setSubmitted] = useState(false)
  const [actionPending, setActionPending] = useState(false)
  const [actionError, setActionError] = useState('')
  const [result, setResult] = useState(() => {
    const state = location.state as { infraResult?: string } | null
    return state?.infraResult ?? ''
  })
  const canBootstrapNetwork = live
    && inventory !== null
    && inventory.networks.length === 0
    && !inventoryPending
    && !inventoryError

  const networkNameError = submitted && networkName.trim().length < 2
    ? 'Enter a network name with at least 2 characters.'
    : submitted && networks.some((network) => network.name.toLowerCase() === networkName.trim().toLowerCase())
      ? 'A network with this name already exists.'
      : undefined
  const addressPoolError = submitted && !isCanonicalIpPrefix(addressPool, { family: 'ipv4', minBits: 8, maxBits: 30 })
    ? 'Use a canonical IPv4 /8 through /30, such as 100.88.3.0/24.'
    : undefined

  const networkColumns: DataColumn<InfrastructureNetwork>[] = [
    {
      key: 'network',
      label: 'Network',
      render: (row) => <Link to={`/infrastructure/networks/${row.id}`}><EntityTitle icon={<Network size={16} />} subtitle={live ? row.id : `net_${row.id.toUpperCase()}`}>{row.name}</EntityTitle></Link>,
    },
    { key: 'cidr', label: 'CIDR', render: (row) => <code>{row.addressPool}</code> },
    { key: 'gateway', label: live ? 'Connectors' : 'Gateway', render: (row) => live ? row.connectors?.length ?? 0 : row.connector.name },
    { key: 'relays', label: 'Relays', render: (row) => relays.filter((relay) => relay.networkId === row.id || relay.networkId === 'all').length },
    { key: 'nodes', label: 'Nodes', render: (row) => row.nodes },
    ...(!live ? [{ key: 'state', label: 'State', render: (row: InfrastructureNetwork) => <Status tone={row.connectedNodes ? 'positive' : 'muted'}>{row.connectedNodes ? 'Healthy' : 'Awaiting connector'}</Status> }] : []),
  ]
  const pendingLiveRoute = inventory?.routes.find(isPendingControllerRoute)
  const workItems = live
    ? [
      pendingLiveRoute ? { kind: 'route', to: `/routes/${pendingLiveRoute.route_id}/approve`, title: 'Approve advertised route', detail: `${pendingLiveRoute.prefix} · metric ${pendingLiveRoute.metric}`, age: 'Pending' } : null,
    ].filter((item): item is { kind: string; to: string; title: string; detail: string; age: string } => Boolean(item))
    : [
      { kind: 'route', to: '/routes/rte_01J8KUBEAPI/approve', title: 'Approve Kubernetes API', detail: '10.24.8.10/32 · requested 8 min ago', age: '8m' },
      { kind: 'relay', to: '/infrastructure/relays/rly_fra02', title: 'Relay certificate aging', detail: 'fra-relay-02 · 14 days remain', age: '1h' },
      { kind: 'node', to: '/nodes/nod_01J8ORACLE9', title: 'Node has gone stale', detail: 'legacy-oracle · 4 days offline', age: '2h' },
    ]

  async function handleCreateNetwork(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitted(true)
    if (live && !canBootstrapNetwork) {
      setActionError('Network creation is unavailable for the current inventory state.')
      return
    }
    const name = networkName.trim()
    const pool = addressPool.trim()
    if (name.length < 2 || networks.some((network) => network.name.toLowerCase() === name.toLowerCase()) || !isCanonicalIpPrefix(pool, { family: 'ipv4', minBits: 8, maxBits: 30 })) return
    setActionPending(true)
    setActionError('')
    try {
      if (live) {
        await request('/v1/admin/networks', { method: 'POST', body: { name, ipv4_pool: pool } })
        await refresh()
      } else {
        addInfrastructureNetwork({ name, addressPool: pool })
      }
      setResult(`${name} created.`)
      setCreatingNetwork(false)
      setNetworkName('')
      setAddressPool(live ? '' : '100.88.3.0/24')
      setSubmitted(false)
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'The network could not be created. Try again.')
    } finally {
      setActionPending(false)
    }
  }

  return (
    <>
      <PageHeader
        title="Infrastructure"
        action={<div className="button-row">{live && !canBootstrapNetwork ? <Button disabled title={networks.length ? 'Additional networks are unavailable in this console.' : 'Network inventory is unavailable.'} variant="secondary"><Plus aria-hidden="true" size={16} /> Add network</Button> : <Button onClick={() => { setCreatingNetwork(true); setResult('') }} variant="secondary"><Plus aria-hidden="true" size={16} /> Add network</Button>}<Button to="/infrastructure/relays/new" variant="primary" disabled={live && !networks.length}><RadioTower aria-hidden="true" size={17} /> Register relay</Button></div>}
      />

      {result ? <div className="infra-success" role="status"><Status>{result}</Status></div> : null}

      {creatingNetwork ? (
        <section className="infra-create-panel" aria-labelledby="infra-create-title">
          <div><h2 id="infra-create-title">Create network</h2><p>Reserves address space only; grants no access or routes.</p></div>
          <FormStack onSubmit={handleCreateNetwork}>
            <Field label="Network name" error={networkNameError}><input aria-invalid={Boolean(networkNameError)} autoFocus maxLength={80} onChange={(event) => setNetworkName(event.target.value)} value={networkName} /></Field>
            <Field label="IPv4 address pool" error={addressPoolError}><input aria-invalid={Boolean(addressPoolError)} onChange={(event) => setAddressPool(event.target.value)} value={addressPool} /></Field>
            {actionError ? <p className="infra-form-error" role="alert">{actionError}</p> : null}
            <div className="button-row"><Button disabled={actionPending} type="submit" variant="primary">{actionPending ? 'Creating…' : 'Create network'}</Button><Button disabled={actionPending} onClick={() => { setCreatingNetwork(false); setSubmitted(false); setActionError('') }} variant="quiet">Cancel</Button></div>
          </FormStack>
        </section>
      ) : null}

      <div className={`infra-health-strip${live ? ' is-live' : ''}`} aria-label="Infrastructure summary">
        <div><Network aria-hidden="true" size={16} /><span><strong>{networks.length}</strong><small>Networks</small></span></div>
        <div><RadioTower aria-hidden="true" size={16} /><span><strong>{relays.length}</strong><small>{live ? `${relays.filter((relay) => relay.enabled).length} enabled` : `${relays.filter((relay) => relay.enabled && relay.reachable).length} healthy`}</small></span></div>
        {!live ? <div><CircleGauge aria-hidden="true" size={16} /><span><strong>86%</strong><small>Direct paths</small></span></div> : null}
        {!live ? <div><Clock3 aria-hidden="true" size={16} /><span><strong>24 ms</strong><small>Median latency</small></span></div> : null}
      </div>

      {inventoryPending ? <p className="infra-inventory-message" role="status">Refreshing controller inventory…</p> : null}
      {inventoryError ? <p className="infra-form-error" role="alert">Controller inventory is unavailable: {inventoryError}</p> : null}

      <div className={`infra-topology-grid${live ? ' is-live' : ''}`}>
        {!live ? <section className="infra-panel infra-topology-panel" aria-labelledby="infra-topology-title">
          <div className="infra-panel-head"><div><h2 id="infra-topology-title">Network topology</h2></div></div>
          <div className="infra-topology" role="img" aria-label="Network and relay topology">
            <svg viewBox="0 0 760 270" preserveAspectRatio="none" aria-hidden="true">
              <path className="infra-topology-path is-active" d="M105 135 C220 42 335 45 430 112 S602 196 665 135" />
              <path className="infra-topology-path" d="M105 135 C228 224 348 222 430 159 S590 64 665 135" />
            </svg>
            <div className="infra-topology-node infra-control"><ServerCog aria-hidden="true" size={17} /><span><strong>Controller</strong></span></div>
            <div className="infra-topology-relays">
              {relays.slice(0, 3).map((relay) => <Link key={relay.id} to={`/infrastructure/relays/${relay.id}`}><span className={`infra-state-light ${relay.enabled && relay.reachable ? 'is-healthy' : 'is-warning'}`} />{relay.name}<small>{relay.sessions} fallback</small></Link>)}
            </div>
            <div className="infra-topology-node infra-networks-node"><Network aria-hidden="true" size={17} /><span><strong>{networks.length} private networks</strong><small>{networks.reduce((total, network) => total + network.routes, 0)} published routes</small></span></div>
          </div>
          <div className="infra-relay-links" aria-label="Relay inventory">
            {relays.map((relay) => <Link key={relay.id} to={`/infrastructure/relays/${relay.id}`}><RadioTower aria-hidden="true" size={14} /><span>{relay.name}</span><Status tone={!relay.enabled ? 'muted' : relay.reachable ? 'positive' : 'warning'}>{!relay.enabled ? 'Disabled' : relay.reachable ? 'Reachable' : 'Awaiting probe'}</Status></Link>)}
          </div>
        </section> : null}

        <aside className="infra-panel infra-work-queue" aria-labelledby="infra-work-title">
          <div className="infra-panel-head"><div><h2 id="infra-work-title">Needs attention</h2></div><span className="infra-queue-count">{workItems.length}</span></div>
          {workItems.map((item) => <Link key={`${item.kind}-${item.to}`} to={item.to}><span className={`infra-queue-icon ${item.kind === 'relay' ? 'is-danger' : 'is-warning'}`}>{item.kind === 'route' ? <TriangleAlert aria-hidden="true" size={16} /> : item.kind === 'relay' ? <RadioTower aria-hidden="true" size={16} /> : <ServerCog aria-hidden="true" size={16} />}</span><span><strong>{item.title}</strong><small>{item.detail}</small></span><time>{item.age}</time></Link>)}
          {!workItems.length ? <div className="infra-queue-empty"><ShieldCheck aria-hidden="true" size={18} /><span><strong>No pending routes</strong></span></div> : null}
          <Button to="/audit" variant="quiet">Review all activity</Button>
        </aside>
      </div>

      <Section title="Networks">
        <DataTable columns={networkColumns} empty={<p className="infra-empty-copy">{live ? 'No network is configured.' : 'No networks remain. Create one before enrolling nodes or publishing routes.'}</p>} rowKey={(row) => row.id} rows={networks} />
      </Section>
    </>
  )
}
