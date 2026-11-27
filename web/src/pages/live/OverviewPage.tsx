import { Activity, ArrowRight, CheckCircle2, Clock3, FileKey2, MonitorDot, Network, Route as RouteIcon, ShieldCheck } from 'lucide-react'
import { Button, Callout, PageHeader } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'
import { ErrorMessage, SummaryStrip, auditActor, certificateState, nodeState, routeState, time } from './shared'
import './live-overview.css'

export function OverviewPage() {
  const { inventory, inventoryPending, inventoryError, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const canReadNodes = Boolean(networkId && hasPermission('node.read', networkId))
  const canReadRoutes = Boolean(networkId && hasPermission('route.read', networkId))
  const canReadRules = Boolean(networkId && hasPermission('acl.read', networkId))
  const canReadRelays = Boolean(networkId && hasPermission('relay.read', networkId))
  const currentNodes = inventory?.nodes.filter((node) => !nodeState(node).inactive) ?? []
  const currentRoutes = inventory?.routes.filter((route) => routeState(route).actionable) ?? []
  const enabledRules = inventory?.aclRules.filter((rule) => rule.enabled) ?? []
  const enabledRelays = inventory?.relays.filter((relay) => relay.enabled) ?? []
  const advertisedRoutes = inventory?.routes.filter((route) => route.state === 'advertised' && routeState(route).actionable) ?? []
  const invalidCertificates = inventory?.certificates.filter((certificate) => certificateState(certificate).label !== 'Valid') ?? []
  const recentEvents = [...(inventory?.auditEvents ?? [])].sort((left, right) => right.created_at_unix_seconds - left.created_at_unix_seconds).slice(0, 4)
  const description = inventory?.network ? `${inventory.network.name} · ${inventory.network.ipv4_pool}` : undefined
  const quickActions = networkId ? [
    hasPermission('enrollment.issue', networkId) ? { label: 'Add node', to: '/nodes/new', icon: MonitorDot } : null,
    hasPermission('route.manage', networkId) ? { label: 'Assign route', to: '/routes/new', icon: RouteIcon } : null,
    hasPermission('acl.manage', networkId) ? { label: 'Create rule', to: '/access/new', icon: ShieldCheck } : null,
  ].filter(Boolean) as Array<{ label: string; to: string; icon: typeof MonitorDot }> : []
  return <>
    <PageHeader title="Overview" description={description} action={quickActions.length ? <div className="button-row">{quickActions.map(({ label, to, icon: Icon }, index) => (
      <Button key={to} to={to} variant={index === 0 ? 'primary' : 'secondary'}><Icon aria-hidden="true" size={15} />{label}</Button>
    ))}</div> : undefined} />
    <ErrorMessage value={inventoryError} />
    {inventoryPending ? <p role="status">Refreshing inventory…</p> : null}
    {inventory && inventory.networks.length > 1 && !inventory.network ? <Callout>Select a network.</Callout> : null}
    {inventory ? <>
      <SummaryStrip label="Network inventory summary" items={[
        { label: 'Current nodes', value: canReadNodes ? currentNodes.length : '—', detail: canReadNodes ? undefined : 'Not authorized' },
        { label: 'Current routes', value: canReadRoutes ? currentRoutes.length : '—', detail: canReadRoutes ? `${advertisedRoutes.length} awaiting approval` : 'Not authorized', tone: canReadRoutes && advertisedRoutes.length ? 'warning' : undefined },
        { label: 'Enabled relays', value: canReadRelays ? enabledRelays.length : '—', detail: canReadRelays ? undefined : 'Not authorized' },
        { label: 'Enabled rules', value: canReadRules ? enabledRules.length : '—', detail: canReadRules ? `${enabledRules.filter((rule) => rule.action === 'accept').length} allow` : 'Not authorized' },
      ]} />
      <div className="live-overview">
        <section className="live-overview__panel" aria-labelledby="overview-networks">
          <header><h2 id="overview-networks">Networks <small>{inventory.networks.length}</small></h2><Button to="/networks" variant="quiet">View networks <ArrowRight aria-hidden="true" size={14} /></Button></header>
          {inventory.networks.length ? <ul className="live-overview__list">{inventory.networks.map((network) => (
            <li className="live-overview__row" key={network.network_id}>
              <Network aria-hidden="true" size={16} />
              <span><strong>{network.name}</strong><small><code>{network.ipv4_pool}</code></small></span>
              {network.network_id === networkId ? <small>Current</small> : null}
            </li>
          ))}</ul> : <p className="live-overview__empty"><Network aria-hidden="true" size={16} />No networks</p>}
        </section>
        <section className="live-overview__panel" aria-labelledby="overview-attention">
          <header><h2 id="overview-attention">Needs attention</h2></header>
          {advertisedRoutes.length ? <Button className="live-overview__row" to="/routes" variant="quiet"><Clock3 aria-hidden="true" size={16} /><span>{advertisedRoutes.length} {advertisedRoutes.length === 1 ? 'route needs' : 'routes need'} review</span><ArrowRight aria-hidden="true" size={14} /></Button> : null}
          {invalidCertificates.length ? <Button className="live-overview__row" to="/security" variant="quiet"><FileKey2 aria-hidden="true" size={16} /><span>{invalidCertificates.length} inactive {invalidCertificates.length === 1 ? 'certificate' : 'certificates'}</span><ArrowRight aria-hidden="true" size={14} /></Button> : null}
          {!advertisedRoutes.length && !invalidCertificates.length ? <p className="live-overview__empty"><CheckCircle2 aria-hidden="true" size={16} />No listed review items</p> : null}
        </section>
        <section className="live-overview__panel live-overview__activity" aria-labelledby="overview-activity">
          <header><h2 id="overview-activity">Recent activity</h2><Button to="/audit" variant="quiet">Audit log <ArrowRight aria-hidden="true" size={14} /></Button></header>
          {recentEvents.length ? <ul className="live-overview__list">{recentEvents.map((event) => (
            <li className="live-overview__row" key={event.event_id}>
              <Activity aria-hidden="true" size={16} />
              <span><strong>{event.action}</strong><small>{auditActor(event)}</small></span>
              <time>{time(event.created_at_unix_seconds)}</time>
            </li>
          ))}</ul> : <p className="live-overview__empty"><Activity aria-hidden="true" size={16} />No activity</p>}
        </section>
      </div>
    </> : null}
  </>
}
