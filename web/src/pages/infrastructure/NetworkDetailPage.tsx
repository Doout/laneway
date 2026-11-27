import { useState } from 'react'
import { AlertTriangle, Laptop, Network, Plus, RadioTower, Route, ServerCog, TriangleAlert } from 'lucide-react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Button, Callout, ConfirmPanel, DataTable, EmptyState, EntityTitle, Field, PageHeader, Status, type DataColumn } from '../../components/ui'
import { INFRASTRUCTURE_ACTOR, deleteInfrastructureNetwork } from '../../lib/infrastructure-state'
import { isPendingControllerRoute } from '../../lib/live-records'
import { useInfrastructureView } from './useInfrastructureView'
import './infrastructure.css'

interface ConnectorRecord {
  id: string
  name: string
  routes: number
  sessions: string
  state: 'Connected' | 'Enrolled' | 'Offline'
}

const connectorColumns: DataColumn<ConnectorRecord>[] = [
  { key: 'connector', label: 'Connector', render: (row) => <Link to={`/nodes/${row.id}`}><EntityTitle icon={<ServerCog size={16} />} subtitle={row.id}>{row.name}</EntityTitle></Link> },
  { key: 'routes', label: 'Routes', render: (row) => row.routes },
  { key: 'sessions', label: 'Sessions', render: (row) => row.sessions },
  { key: 'state', label: 'State', render: (row) => <Status tone={row.state === 'Offline' ? 'muted' : 'positive'}>{row.state}</Status> },
]

export function NetworkDetailPage() {
  const { networkId } = useParams()
  const navigate = useNavigate()
  const { networks, relays, live, inventory, hasPermission } = useInfrastructureView()
  const network = networks.find((record) => record.id === networkId)
  const [confirmingDelete, setConfirmingDelete] = useState(false)
  const [confirmation, setConfirmation] = useState('')

  if (!network) {
    return <EmptyState icon={<Network size={32} />} title="Network not found" description={`No network matches “${networkId ?? 'unknown'}”.`} action={<Button to="/infrastructure" variant="primary">Return to infrastructure</Button>} />
  }

  const selectedNetwork = network
  const networkRelays = relays.filter((relay) => relay.networkId === network.id || relay.networkId === 'all')
  const pendingRouteId = live
    ? inventory?.routes.find((route) => route.network_id === network.id && isPendingControllerRoute(route))?.route_id
    : 'rte_01J8KUBEAPI'
  const connectorRows: ConnectorRecord[] = live
    ? (network.connectors ?? []).map((connector) => ({ ...connector, routes: inventory?.routes.filter((route) => route.node_id === connector.id).length ?? 0, state: 'Enrolled' }))
    : network.connector.id === 'none' ? [] : [{ ...network.connector, routes: network.routes, state: network.connector.state }]
  const visibleConnectorColumns = live ? connectorColumns.filter((column) => column.key !== 'sessions') : connectorColumns
  const deletionImpact = `Deleting ${network.name} withdraws ${network.routes} routes, removes address assignment for ${network.nodes} nodes, and removes access for ${network.userEnrollments} user enrollments. ${networkRelays.length} assigned relay${networkRelays.length === 1 ? '' : 's'} will be changed to All networks. Node and relay records are retained.`
  const canManageRoutes = !live || hasPermission('route.manage', network.id)
  const canIssueEnrollment = !live || hasPermission('enrollment.issue', network.id)

  function handleDelete() {
    if (confirmation !== selectedNetwork.name) return
    deleteInfrastructureNetwork(selectedNetwork.id)
    navigate('/infrastructure', { replace: true, state: { infraResult: `${selectedNetwork.name} deleted by ${INFRASTRUCTURE_ACTOR}. ${selectedNetwork.routes} routes were withdrawn and ${networkRelays.length} relay assignments were updated.` } })
  }

  if (confirmingDelete) {
    return (
      <ConfirmPanel icon={<AlertTriangle size={28} />} title={`Delete ${network.name}?`} description={deletionImpact}>
        <Callout tone="danger">This cannot be undone from the console. Type the exact network name to authorize the change as {INFRASTRUCTURE_ACTOR}.</Callout>
        <div className="infra-confirm-field"><Field label={`Type “${network.name}” to confirm`}><input autoComplete="off" onChange={(event) => setConfirmation(event.target.value)} value={confirmation} /></Field></div>
        <div className="button-row"><Button disabled={confirmation !== network.name} onClick={handleDelete} variant="danger">Delete network</Button><Button onClick={() => { setConfirmingDelete(false); setConfirmation('') }} variant="secondary">Cancel</Button></div>
      </ConfirmPanel>
    )
  }

  return (
    <div className="infra-network-page">
      <PageHeader
        title={`${network.name} network`}
        action={canManageRoutes || canIssueEnrollment ? <div className="button-row">{canManageRoutes ? <Button to="/routes/new" variant="secondary"><Route aria-hidden="true" size={16} /> Add route</Button> : null}{canIssueEnrollment ? <Button to="/nodes/new" variant="primary"><Plus aria-hidden="true" size={16} /> Add node</Button> : null}</div> : undefined}
      />

      <div className="infra-network-facts" role="group" aria-label={`${network.name} summary`}>
        <span><strong>{network.connectedNodes}/{network.nodes}</strong> {live ? 'nodes enrolled' : 'nodes connected'}</span>
        <span><strong>{network.healthyRoutes}/{network.routes}</strong> {live ? 'routes approved' : 'routes healthy'}</span>
        <span><strong>{network.userEnrollments}</strong> user enrollments</span>
      </div>

      <div className="infra-detail-workspace">
        <section className="infra-panel infra-network-path" aria-labelledby="network-connectors-title">
          <div className="infra-panel-head infra-connectors-head"><div><h2 id="network-connectors-title">Connectors</h2></div>{live ? null : network.connector.id === 'none' ? <Button to="/nodes/new" variant="secondary">Add connector</Button> : <Button to={`/nodes/${network.connector.id}`} variant="quiet">Open connector</Button>}</div>
          <DataTable columns={visibleConnectorColumns} empty={<p className="infra-empty-copy">{live ? 'No node has the connector capability enabled.' : 'No connector is assigned. Add a connector before publishing routes.'}</p>} rowKey={(row) => row.id} rows={connectorRows} />
          {!live ? <div className="infra-network-path-section">
            <div className="infra-panel-head"><h3>Network path</h3><Status tone={network.connectedNodes ? 'positive' : 'muted'}>{network.connectedNodes ? 'Healthy' : 'Awaiting connector'}</Status></div>
            <div className="infra-path-steps" role="group" aria-label={`${network.connectedNodes} connected nodes use ${network.connector.name} to reach ${network.routes} routes with relay fallback`}>
              <div><Laptop aria-hidden="true" size={16} /><span><strong>{network.connectedNodes} connected nodes</strong><small>{network.nodes - network.connectedNodes} offline</small></span></div>
              <Link to={network.connector.id === 'none' ? '/nodes/new' : `/nodes/${network.connector.id}`}><ServerCog aria-hidden="true" size={16} /><span><strong>{network.connector.name}</strong><small>QUIC direct · {network.connector.sessions}</small></span></Link>
              <div><Network aria-hidden="true" size={16} /><span><strong>Private services</strong><small>{network.routes} published routes · {network.healthyRoutes} healthy</small></span></div>
              {networkRelays[0] ? <Link to={`/infrastructure/relays/${networkRelays[0].id}`}><RadioTower aria-hidden="true" size={16} /><span><strong>{networkRelays[0].name}</strong><small>Authenticated fallback</small></span></Link> : null}
            </div>
          </div> : null}
        </section>

        <aside className="infra-panel infra-record-inspector" aria-labelledby="network-record-title">
          <div className="infra-panel-head"><div><h2 id="network-record-title">Network record</h2>{!live ? <p>Last changed by {network.updatedBy}</p> : null}</div><span className="infra-record-icon"><Network aria-hidden="true" size={19} /></span></div>
          <dl className="infra-record-list">
            <div><dt>Network ID</dt><dd><code>{live ? network.id : `net_${network.id.toUpperCase()}`}</code></dd></div>
            <div><dt>Address pool</dt><dd><code>{network.addressPool}</code></dd></div>
            <div><dt>IPv6 pool</dt><dd><code>{network.ipv6Pool}</code></dd></div>
            <div><dt>{live ? 'Relays' : 'Relay fallback'}</dt><dd>{networkRelays.length ? networkRelays.map((relay, index) => <span key={relay.id}>{index ? ', ' : ''}<Link to={`/infrastructure/relays/${relay.id}`}>{relay.name}</Link></span>) : 'None'}</dd></div>
            <div><dt>Created</dt><dd>{network.createdAt}</dd></div>
            {live ? <div><dt>Configuration epoch</dt><dd>{network.configurationEpoch ?? '—'}</dd></div> : <><div><dt>Last result</dt><dd>{network.lastAction}</dd></div><div><dt>Recorded</dt><dd>{network.updatedAt}</dd></div></>}
          </dl>
          {network.routes > network.healthyRoutes ? <div className="infra-inspector-callout"><TriangleAlert aria-hidden="true" size={17} /><p><strong>Route pending.</strong> It is not distributed until approved.</p></div> : null}
          <div className="infra-inspector-actions">{network.routes > network.healthyRoutes && pendingRouteId ? <Button to={canManageRoutes ? `/routes/${pendingRouteId}/approve` : `/routes/${pendingRouteId}`} variant="primary">Review pending route</Button> : null}{!live ? <Button onClick={() => setConfirmingDelete(true)} variant="quiet">Delete network</Button> : null}</div>
        </aside>
      </div>
    </div>
  )
}
