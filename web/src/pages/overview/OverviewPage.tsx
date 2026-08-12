import { ArrowRight, MonitorDot, RadioTower, Route, ShieldCheck, TriangleAlert } from 'lucide-react'
import { Button, Callout, PageHeader, Status } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'
import { controllerNodes, isPendingControllerRoute } from '../../lib/live-records'
import { persistedNodes } from '../../lib/persisted-demo-state'
import './overview.css'

const attempts = [
  { node: 'operator-laptop', destination: 'atlas-gateway', path: 'Direct QUIC', latency: '24 ms', time: '10:22:41', tone: 'positive' as const },
  { node: 'warehouse-scanner-07', destination: 'inventory-api', path: 'Relay fallback', latency: '71 ms', time: '10:21:08', tone: 'warning' as const },
  { node: 'ops-workstation', destination: 'staging-db', path: 'Direct QUIC', latency: '31 ms', time: '10:18:54', tone: 'positive' as const },
  { node: 'finance-laptop', destination: 'atlas-gateway', path: 'Policy denied', latency: '—', time: '10:14:16', tone: 'danger' as const },
]

export function OverviewPage() {
  const { live, inventory, inventoryError, inventoryPending } = useControlPlane()
  const demoRecords = persistedNodes()
  const liveRecords = controllerNodes(inventory?.nodes ?? [])
  const pendingRoutes = live ? inventory?.routes.filter(isPendingControllerRoute).length ?? 0 : 2
  const nodeCount = live ? liveRecords.length : 18
  const routeCount = live ? inventory?.routes.length ?? 0 : 12
  const relayCount = live ? inventory?.relays.filter(relay => relay.enabled).length ?? 0 : 3
  const ruleCount = live ? inventory?.aclRules.filter(rule => rule.enabled).length ?? 0 : 7
  const summary = [inventory?.network?.name, pendingRoutes ? `${pendingRoutes} route${pendingRoutes === 1 ? '' : 's'} pending` : undefined]
    .filter(Boolean)
    .join(' · ') || undefined
  const topologyNames = demoRecords.filter(node => node.state !== 'Revoked').slice(0, 3).map(node => node.name)
  const leftNode = topologyNames[0] ?? 'operator-laptop'
  const rightNode = topologyNames[1] ?? 'atlas-gateway'
  const leftAddress = '100.88.0.23'
  const rightAddress = '10.24.0.0/16'
  const pendingRouteItem = pendingRoutes ? <Button className="attention-item" to="/routes?state=pending" variant="quiet"><span className="attention-item__icon attention-item__icon--warning"><TriangleAlert size={17} /></span><span><strong>{pendingRoutes} route{pendingRoutes === 1 ? '' : 's'} await approval</strong></span><ArrowRight size={16} /></Button> : null

  return <>
    <PageHeader
      title="Overview"
      description={summary}
    />

    {inventoryError ? <Callout tone="danger">{inventoryError}</Callout> : null}
    {inventoryPending ? <div className="overview-loading" role="status">Refreshing inventory…</div> : null}

    {!live || inventory ? <section className="overview-metrics" aria-label="Network inventory summary">
      <div><MonitorDot aria-hidden="true" size={17} /><span><strong>{nodeCount}</strong>{live ? 'Nodes' : 'Active nodes'}</span></div>
      <div><Route aria-hidden="true" size={17} /><span><strong>{routeCount}</strong>Routes</span></div>
      <div><RadioTower aria-hidden="true" size={17} /><span><strong>{relayCount}</strong>Enabled relays</span></div>
      <div><ShieldCheck aria-hidden="true" size={17} /><span><strong>{ruleCount}</strong>Enabled rules</span></div>
    </section> : null}

    {live ? pendingRouteItem ? <section className="attention-panel">
      <div className="panel-heading"><h2>Needs attention</h2><span className="attention-count">{pendingRoutes}</span></div>
      {pendingRouteItem}
    </section> : null : <div className="overview-workspace">
      <div className="overview-main">
        <section className="topology-panel">
          <div className="panel-heading"><h2>Topology</h2><Status tone="positive">Healthy</Status></div>
          <div className="topology-map" aria-label={`${leftNode} to ${rightNode}`}>
            <div className="topology-grid" aria-hidden="true" />
            <div className="topology-node topology-node--client"><span className="topology-node__icon"><MonitorDot size={20} /></span><strong>{leftNode}</strong><small>{leftAddress}</small></div>
            <div className="topology-line topology-line--first"><i /></div>
            <div className="topology-node topology-node--relay"><span className="topology-node__icon"><RadioTower size={20} /></span><strong>Direct</strong><small>QUIC</small></div>
            <div className="topology-line topology-line--second"><i /></div>
            <div className="topology-node topology-node--destination"><span className="topology-node__icon"><Route size={20} /></span><strong>{rightNode}</strong><small>{rightAddress}</small></div>
          </div><div className="topology-path-strip">
            <span><small>Path</small><strong>Direct QUIC</strong></span><i aria-hidden="true" /><span><small>Round trip</small><strong>24 ms</strong></span><i aria-hidden="true" /><span><small>Tunnel</small><strong>WireGuard</strong></span><i aria-hidden="true" /><span><small>Fallback</small><strong>relay-us-east</strong></span>
          </div>
        </section>

        <section className="attempts-panel">
          <div className="panel-heading"><h2>Connection attempts</h2><Button to="/audit" variant="quiet">View audit</Button></div>
          <div className="attempts-table-wrap"><table className="attempts-table"><thead><tr><th>Source</th><th>Destination</th><th>Selected path</th><th>Latency</th><th>Time</th></tr></thead><tbody>{attempts.map(attempt => <tr key={`${attempt.node}-${attempt.time}`}><td><strong>{attempt.node}</strong></td><td>{attempt.destination}</td><td><Status tone={attempt.tone}>{attempt.path}</Status></td><td><code>{attempt.latency}</code></td><td>{attempt.time}</td></tr>)}</tbody></table></div>
        </section>
      </div>

      <aside className="attention-panel">
        <div className="panel-heading"><h2>Needs attention</h2><span className="attention-count">{pendingRoutes + 1}</span></div>
        {pendingRouteItem}
        <Button className="attention-item" to="/nodes" variant="quiet"><span className="attention-item__icon"><MonitorDot size={17} /></span><span><strong>One node uses relay fallback</strong></span><ArrowRight size={16} /></Button>
      </aside>
    </div>}
  </>
}
