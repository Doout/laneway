import { Activity, ArrowRight, CheckCircle2, Clock3, FileKey2, MonitorDot, Network, Route as RouteIcon, ShieldCheck } from 'lucide-react'
import { Button, Callout, PageHeader } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'
import { formatControllerAuditAction } from '../audit/AuditPage'
import { OverviewSection } from '../overview/OverviewSection'
import { ErrorMessage, SummaryStrip, auditActor, certificateState, nodeState, routeState, time } from './shared'

export function OverviewPage() {
  const { inventory, inventoryPending, inventoryError, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const canReadNodes = Boolean(networkId && hasPermission('node.read', networkId))
  const canReadRoutes = Boolean(networkId && hasPermission('route.read', networkId))
  const canReadRules = Boolean(networkId && hasPermission('acl.read', networkId))
  const canReadRelays = Boolean(networkId && hasPermission('relay.read', networkId))
  const canReadCertificates = Boolean(networkId && hasPermission('certificate.read', networkId))
  const canReadAudit = hasPermission('audit.read_global') || Boolean(networkId && hasPermission('audit.read', networkId))
  const currentNodes = inventory?.nodes.filter(node => !nodeState(node).inactive) ?? []
  const currentRoutes = inventory?.routes.filter(route => routeState(route).actionable) ?? []
  const enabledRules = inventory?.aclRules.filter(rule => rule.enabled) ?? []
  const enabledRelays = inventory?.relays.filter(relay => relay.enabled) ?? []
  const advertisedRoutes = currentRoutes.filter(route => route.state === 'advertised')
  const invalidCertificates = inventory?.certificates.filter(certificate => certificateState(certificate).label !== 'Valid') ?? []
  const attentionCount = (canReadRoutes ? advertisedRoutes.length : 0) + (canReadCertificates ? invalidCertificates.length : 0)
  const recentEvents = [...(inventory?.auditEvents ?? [])].sort((left, right) => right.created_at_unix_seconds - left.created_at_unix_seconds).slice(0, 4)
  const description = inventory?.network ? `${inventory.network.name} · ${inventory.network.ipv4_pool}` : undefined
  const quickActions = networkId ? [
    hasPermission('enrollment.issue', networkId) && { label: 'Add node', to: '/nodes/new', icon: MonitorDot },
    hasPermission('route.manage', networkId) && { label: 'Assign route', to: '/routes/new', icon: RouteIcon },
    hasPermission('acl.manage', networkId) && { label: 'Create rule', to: '/access/new', icon: ShieldCheck },
  ].filter(action => action !== false) : []

  return <>
    <PageHeader title="Overview" description={description} action={quickActions.length ? <div className="button-row">{quickActions.map(({ label, to, icon: Icon }, index) => (
      <Button key={to} to={to} variant={index === 0 ? 'primary' : 'secondary'}><Icon aria-hidden="true" size={15} />{label}</Button>
    ))}</div> : undefined} />
    <ErrorMessage value={inventoryError} />
    {inventoryPending ? <p className="overview-loading" role="status">Refreshing inventory…</p> : null}
    {inventory && inventory.networks.length > 1 && !inventory.network ? <Callout>Select a network to view its inventory.</Callout> : null}
    {inventory ? <div className="overview-board">
      {networkId ? <SummaryStrip label="Network inventory summary" items={[
        { label: 'Current nodes', value: canReadNodes ? currentNodes.length : '—', detail: canReadNodes ? undefined : 'Not authorized' },
        { label: 'Current routes', value: canReadRoutes ? currentRoutes.length : '—', detail: canReadRoutes ? undefined : 'Not authorized' },
        { label: 'Enabled relays', value: canReadRelays ? enabledRelays.length : '—', detail: canReadRelays ? undefined : 'Not authorized' },
        { label: 'Enabled rules', value: canReadRules ? enabledRules.length : '—', detail: canReadRules ? `${enabledRules.filter(rule => rule.action === 'accept').length} allow` : 'Not authorized' },
      ]} /> : null}
      <div className="overview-board__columns">
        <div className="overview-board__column">
          {canReadRoutes || canReadCertificates ? <OverviewSection id="overview-attention" title="Needs attention" count={attentionCount}>
            {canReadRoutes && advertisedRoutes.length ? <Button className="overview-row" to="/routes" variant="quiet">
              <Clock3 className="overview-row__warning" aria-hidden="true" size={16} />
              <span>{advertisedRoutes.length} {advertisedRoutes.length === 1 ? 'route awaits' : 'routes await'} approval</span>
              <ArrowRight aria-hidden="true" size={14} />
            </Button> : null}
            {canReadCertificates && invalidCertificates.length ? <Button className="overview-row" to="/security" variant="quiet">
              <FileKey2 className="overview-row__warning" aria-hidden="true" size={16} />
              <span>{invalidCertificates.length} inactive {invalidCertificates.length === 1 ? 'certificate' : 'certificates'}</span>
              <ArrowRight aria-hidden="true" size={14} />
            </Button> : null}
            {!attentionCount ? <p className="overview-empty"><CheckCircle2 aria-hidden="true" size={16} />No items to review</p> : null}
          </OverviewSection> : null}
          <OverviewSection id="overview-networks" title="Networks" count={inventory.networks.length} action={canReadNodes ? { label: 'View networks', to: '/networks' } : undefined}>
            {inventory.networks.length ? <ul className="overview-list">{inventory.networks.map(network => (
              <li className="overview-row" key={network.network_id}>
                <Network aria-hidden="true" size={16} />
                <span><strong>{network.name}</strong><small><code>{network.ipv4_pool}</code></small></span>
                {network.network_id === networkId ? <small>Current</small> : null}
              </li>
            ))}</ul> : <p className="overview-empty"><Network aria-hidden="true" size={16} />No networks</p>}
          </OverviewSection>
        </div>
        {canReadAudit ? <OverviewSection id="overview-activity" title="Recent activity" action={{ label: 'Audit log', to: '/audit' }}>
          {recentEvents.length ? <ul className="overview-list">{recentEvents.map(event => (
            <li className="overview-row" key={event.event_id}>
              <Activity aria-hidden="true" size={16} />
              <span><strong>{formatControllerAuditAction(event.action)}</strong><small>{auditActor(event)}</small></span>
              <time dateTime={new Date(event.created_at_unix_seconds * 1000).toISOString()}>{time(event.created_at_unix_seconds)}</time>
            </li>
          ))}</ul> : <p className="overview-empty"><Activity aria-hidden="true" size={16} />No activity</p>}
        </OverviewSection> : null}
      </div>
    </div> : null}
  </>
}
