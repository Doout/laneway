import { Activity, ArrowRight, ArrowUpRight, CheckCircle2, Clock3, FileKey2, MonitorDot, Network, Route as RouteIcon, ShieldCheck } from 'lucide-react'
import { Button, Callout, PageHeader } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'
import { DashboardEmpty, ErrorMessage, SummaryStrip, auditActor, certificateState, nodeState, routeState, time } from './shared'

export function OverviewPage() {
  const { inventory, inventoryPending, inventoryError, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const activeNodes = inventory?.nodes.filter((node) => !nodeState(node).inactive) ?? []
  const activeRoutes = inventory?.routes.filter((route) => routeState(route).actionable) ?? []
  const activeRules = inventory?.aclRules.filter((rule) => rule.enabled) ?? []
  const activeRelays = inventory?.relays.filter((relay) => relay.enabled) ?? []
  const advertisedRoutes = inventory?.routes.filter((route) => route.state === 'advertised' && routeState(route).actionable) ?? []
  const invalidCertificates = inventory?.certificates.filter((certificate) => certificateState(certificate).label !== 'Valid') ?? []
  const recentEvents = [...(inventory?.auditEvents ?? [])].sort((left, right) => right.created_at_unix_seconds - left.created_at_unix_seconds).slice(0, 4)
  const quickActions = networkId ? [
    hasPermission('enrollment.issue', networkId) ? { label: 'Add node', to: '/nodes/new', icon: MonitorDot } : null,
    hasPermission('route.manage', networkId) ? { label: 'Assign route', to: '/routes/new', icon: RouteIcon } : null,
    hasPermission('acl.manage', networkId) ? { label: 'Create rule', to: '/access/new', icon: ShieldCheck } : null,
  ].filter(Boolean) as Array<{ label: string; to: string; icon: typeof MonitorDot }> : []
  return <>
    <PageHeader title="Overview" action={<Button to="/networks" variant="secondary">Open networks <ArrowUpRight size={15} /></Button>} />
    <ErrorMessage value={inventoryError} />
    {inventoryPending ? <p role="status">Refreshing inventory…</p> : null}
    {inventory && inventory.networks.length > 1 && !inventory.network ? <Callout>Select a network.</Callout> : null}
    {inventory ? <>
      <section className="workspace-hero" aria-label="Workspace status">
        <div className="workspace-hero__copy"><span className="workspace-hero__eyebrow"><CheckCircle2 aria-hidden="true" size={15} /> Online</span><h2>{inventory.network?.name ?? 'Laneway'}</h2><p>{inventory.network ? inventory.network.ipv4_pool : `${inventory.networks.length} networks`}</p><div className="workspace-hero__actions">{quickActions.map(({ label, to, icon: Icon }, index) => <Button key={to} to={to} variant={index === 0 ? 'primary' : 'secondary'}><Icon aria-hidden="true" size={15} />{label}</Button>)}</div></div>
        <div className="workspace-hero__pulse"><span><Activity aria-hidden="true" size={18} /></span><div><strong>{activeNodes.length + activeRelays.length}</strong><small>active nodes and relays</small></div><div><strong>{activeRoutes.length + activeRules.length}</strong><small>active routes and rules</small></div></div>
      </section>
      <SummaryStrip label="Network inventory summary" items={[
        { label: 'Networks', value: inventory.networks.length },
        { label: 'Active nodes', value: activeNodes.length, tone: 'positive' },
        { label: 'Routes active', value: activeRoutes.length, detail: `${advertisedRoutes.length} awaiting approval`, tone: advertisedRoutes.length ? 'warning' : undefined },
        { label: 'Rules', value: activeRules.length, detail: `${activeRules.filter((rule) => rule.action === 'accept').length} allow` },
      ]} />
      <div className="overview-dashboard">
        <section className="dashboard-panel dashboard-panel--networks"><header><div><h2>Networks</h2></div><Button to="/networks" variant="quiet">View all <ArrowRight size={14} /></Button></header><div className="overview-network-list">{inventory.networks.map((network) => <div key={network.network_id} className={network.network_id === networkId ? 'is-current' : undefined}><span className="overview-network-list__icon"><Network aria-hidden="true" size={17} /></span><span><strong>{network.name}</strong><small>{network.ipv4_pool}</small></span>{network.network_id === networkId ? <em>Current</em> : null}</div>)}</div></section>
        <section className="dashboard-panel"><header><div><h2>Needs attention</h2></div></header><div className="attention-list">{advertisedRoutes.length ? <Button to="/routes" variant="quiet"><Clock3 size={15} /><span><strong>{advertisedRoutes.length} route {advertisedRoutes.length === 1 ? 'needs' : 'need'} review</strong></span><ArrowRight size={14} /></Button> : null}{invalidCertificates.length ? <Button to="/security" variant="quiet"><FileKey2 size={15} /><span><strong>{invalidCertificates.length} inactive {invalidCertificates.length === 1 ? 'certificate' : 'certificates'}</strong></span><ArrowRight size={14} /></Button> : null}{!advertisedRoutes.length && !invalidCertificates.length ? <DashboardEmpty icon={<CheckCircle2 size={18} />} title="Nothing needs attention" /> : null}</div></section>
        <section className="dashboard-panel dashboard-panel--activity"><header><div><h2>Recent activity</h2></div><Button to="/audit" variant="quiet">Audit log <ArrowRight size={14} /></Button></header>{recentEvents.length ? <div className="overview-activity-list">{recentEvents.map((event) => <div key={event.event_id}><span className="overview-activity-list__icon"><Activity aria-hidden="true" size={15} /></span><span><strong>{event.action}</strong><small>{auditActor(event)}</small></span><time>{time(event.created_at_unix_seconds)}</time></div>)}</div> : <DashboardEmpty icon={<Activity size={18} />} title="No activity" />}</section>
      </div>
    </> : null}
  </>
}
