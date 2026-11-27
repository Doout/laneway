import { Activity, ArrowRight, CheckCircle2, Clock3, MonitorDot } from 'lucide-react'
import { Button, Callout, PageHeader, Status } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'
import { useInfrastructureState } from '../../lib/infrastructure-state'
import { controllerNodes, isPendingControllerRoute } from '../../lib/live-records'
import { persistedAccessRules, persistedNodes, persistedRoutes } from '../../lib/persisted-demo-state'
import { SummaryStrip } from '../live/shared'
import { OverviewSection } from './OverviewSection'

const attempts = [
  { node: 'operator-laptop', destination: 'atlas-gateway', path: 'Direct QUIC', latency: '24 ms', time: '10:22:41', tone: 'positive' as const },
  { node: 'warehouse-scanner-07', destination: 'inventory-api', path: 'Relay fallback', latency: '71 ms', time: '10:21:08', tone: 'warning' as const },
  { node: 'ops-workstation', destination: 'staging-db', path: 'Direct QUIC', latency: '31 ms', time: '10:18:54', tone: 'positive' as const },
  { node: 'finance-laptop', destination: 'atlas-gateway', path: 'Policy denied', latency: '—', time: '10:14:16', tone: 'danger' as const },
]

export function OverviewPage() {
  const { live, inventory, inventoryError, inventoryPending } = useControlPlane()
  const demoInfrastructure = useInfrastructureState()
  const nodes = live ? controllerNodes(inventory?.nodes ?? []) : persistedNodes()
  const currentNodes = nodes.filter(node => node.state !== 'Revoked')
  const demoRoutes = live ? [] : persistedRoutes()
  const demoRules = live ? [] : persistedAccessRules()
  const pendingRoutes = live ? inventory?.routes.filter(isPendingControllerRoute).length ?? 0 : demoRoutes.filter(route => route.state === 'Pending approval').length
  const fallbackCount = live ? 0 : currentNodes.filter(node => node.state === 'Relay fallback').length
  const attentionCount = pendingRoutes + fallbackCount
  const routeCount = live ? inventory?.routes.length ?? 0 : demoRoutes.length
  const relayCount = (live ? inventory?.relays ?? [] : demoInfrastructure.relays).filter(relay => relay.enabled).length
  const ruleCount = live ? inventory?.aclRules.filter(rule => rule.enabled).length ?? 0 : demoRules.filter(rule => rule.state === 'Enabled').length

  return <>
    <PageHeader title="Overview" description={inventory?.network?.name} />
    {inventoryError ? <Callout tone="danger">{inventoryError}</Callout> : null}
    {inventoryPending ? <p className="overview-loading" role="status">Refreshing inventory…</p> : null}
    {!live || inventory ? <div className="overview-board">
      <SummaryStrip label="Network inventory summary" items={[
        { label: 'Current nodes', value: currentNodes.length },
        { label: 'Routes', value: routeCount },
        { label: 'Enabled relays', value: relayCount },
        { label: 'Enabled rules', value: ruleCount },
      ]} />
      <div className="overview-board__columns">
        <div className="overview-board__column">
          <OverviewSection id="overview-attention" title="Needs attention" count={attentionCount}>
            {pendingRoutes ? <Button className="overview-row" to="/routes?state=pending" variant="quiet">
              <Clock3 className="overview-row__warning" size={16} aria-hidden="true" />
              <span>{pendingRoutes} {pendingRoutes === 1 ? 'route awaits' : 'routes await'} approval</span>
              <ArrowRight size={14} aria-hidden="true" />
            </Button> : null}
            {fallbackCount ? <Button className="overview-row" to="/nodes" variant="quiet">
              <MonitorDot className="overview-row__warning" size={16} aria-hidden="true" />
              <span>{fallbackCount} {fallbackCount === 1 ? 'node uses' : 'nodes use'} relay fallback</span>
              <ArrowRight size={14} aria-hidden="true" />
            </Button> : null}
            {!attentionCount ? <p className="overview-empty"><CheckCircle2 size={16} aria-hidden="true" />No items to review</p> : null}
          </OverviewSection>
          {!live ? <OverviewSection id="overview-path" title="Sample connection">
            <dl className="overview-path">
              <div><dt>Source</dt><dd>{attempts[0].node}</dd></div>
              <div><dt>Destination</dt><dd>{attempts[0].destination}</dd></div>
              <div><dt>Path</dt><dd>{attempts[0].path}</dd></div>
              <div><dt>Round trip</dt><dd><code>{attempts[0].latency}</code></dd></div>
              <div><dt>Tunnel</dt><dd>WireGuard</dd></div>
              <div><dt>Fallback</dt><dd>relay-us-east</dd></div>
            </dl>
          </OverviewSection> : null}
        </div>
        {!live ? <OverviewSection id="overview-attempts" title="Connection attempts" action={{ label: 'View audit', to: '/audit' }}>
          <ul className="overview-list">
            {attempts.map(attempt => <li className="overview-row" key={attempt.time}>
              <Activity aria-hidden="true" size={16} />
              <div className="overview-row__attempt">
                <span><strong>{attempt.node}</strong><small>to {attempt.destination}</small></span>
                <Status tone={attempt.tone}>{attempt.path}</Status>
              </div>
              <div className="overview-row__timing">
                <small className="overview-row__latency">{attempt.latency}</small>
                <time>{attempt.time}</time>
              </div>
            </li>)}
          </ul>
        </OverviewSection> : null}
      </div>
    </div> : null}
  </>
}
