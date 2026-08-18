import { LayoutDashboard, MonitorDot, Network, RadioTower, RefreshCw, Route, ScrollText, ShieldCheck, Users } from 'lucide-react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import clsx from 'clsx'
import { useState } from 'react'
import { isNetworkScopedAdministratorPermission, useControlPlane, type AdministratorPermission } from '../lib/control-plane'

const navigation: Array<{ group: 'Workspace' | 'Network' | 'Operations'; label: string; to: string; icon: typeof LayoutDashboard; permission: AdministratorPermission }> = [
  { group: 'Workspace', label: 'Overview', to: '/overview', icon: LayoutDashboard, permission: 'network.list' },
  { group: 'Network', label: 'Nodes', to: '/nodes', icon: MonitorDot, permission: 'node.read' },
  { group: 'Network', label: 'Users', to: '/users', icon: Users, permission: 'acl.read' },
  { group: 'Network', label: 'Teams', to: '/teams', icon: Users, permission: 'acl.read' },
  { group: 'Network', label: 'Routes', to: '/routes', icon: Route, permission: 'route.read' },
  { group: 'Network', label: 'Access', to: '/access', icon: ShieldCheck, permission: 'acl.read' },
  { group: 'Operations', label: 'Infrastructure', to: '/infrastructure', icon: Network, permission: 'network.list' },
  { group: 'Operations', label: 'Security', to: '/security', icon: RadioTower, permission: 'certificate.read' },
  { group: 'Operations', label: 'Audit', to: '/audit', icon: ScrollText, permission: 'audit.read' },
]

const pathLabels: Record<string, string> = {
  overview: 'Overview', nodes: 'Nodes', users: 'Users', teams: 'Teams', routes: 'Routes', infrastructure: 'Infrastructure',
  access: 'Access', security: 'Security', audit: 'Audit', new: 'New', approve: 'Approve', revoke: 'Revoke', capabilities: 'Capabilities',
}

function breadcrumbLabel(pathname: string) {
  const segment = pathname.split('/').filter(Boolean).at(-1) ?? 'overview'
  if (pathLabels[segment]) return pathLabels[segment]
  return segment.length > 18 ? `${segment.slice(0, 8)}…${segment.slice(-4)}` : segment
}

function BrandMark() {
  return <span className="brand-mark" aria-hidden="true"><span /><span /><span /></span>
}

export function LiveAppShell() {
  const location = useLocation()
  const navigate = useNavigate()
  const [rotationPending, setRotationPending] = useState(false)
  const [signOutPending, setSignOutPending] = useState(false)
  const { session, inventory, inventoryError, inventoryPending, authPending, authError, selectedNetworkId, selectNetwork, hasPermission, refresh, rotateSession, signOut } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const visibleNavigation = navigation.filter((item) => {
    if (item.to === '/audit' && hasPermission('audit.read_global')) return true
    if (!isNetworkScopedAdministratorPermission(item.permission)) return hasPermission(item.permission)
    return Boolean(networkId && hasPermission(item.permission, networkId))
  })

  async function handleSignOut() {
    setSignOutPending(true)
    try {
      if (await signOut()) navigate('/sign-in', { replace: true })
    } finally {
      setSignOutPending(false)
    }
  }

  async function handleRotation() {
    setRotationPending(true)
    try {
      await rotateSession()
    } finally {
      setRotationPending(false)
    }
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <Link to="/overview" className="wordmark" aria-label="Laneway overview"><BrandMark /><span>Laneway</span></Link>
      <nav className="sidebar-nav" aria-label="Primary navigation">
        {(['Workspace', 'Network', 'Operations'] as const).map((group) => {
          const items = visibleNavigation.filter((item) => item.group === group)
          return items.length ? <section className="sidebar-nav__group" key={group} aria-label={group}>
            {group !== 'Workspace' ? <span className="sidebar-nav__label">{group}</span> : null}
            {items.map((item) => {
            const Icon = item.icon
            return <NavLink key={item.to} to={item.to} className={({ isActive }) => clsx('sidebar-nav__item', isActive && 'is-active')}>
              <Icon aria-hidden="true" size={17} /><span>{item.label}</span>
            </NavLink>
            })}
          </section> : null
        })}
      </nav>
      {inventory?.network ? <div className="sidebar-environment"><span className="sidebar-environment__icon"><Network aria-hidden="true" size={17} /></span><span><strong>{inventory.network.name}</strong></span></div> : null}
    </aside>
    <div className="app-frame">
      <header className="command-bar">
        <nav className="breadcrumbs" aria-label="Breadcrumb"><Link to="/overview">Laneway</Link><span aria-hidden="true">/</span><span>{breadcrumbLabel(location.pathname)}</span></nav>
        <div className="command-bar__tools">
          <div className={clsx('inventory-health', inventoryError && 'is-error')} role="status"><span aria-hidden="true" />{inventoryError || (inventoryPending ? 'Refreshing' : inventory ? 'Connected' : 'Connecting')}</div>
          {inventory && inventory.networks.length > 1 ? <label className="network-selector"><span className="sr-only">Selected network</span><select aria-label="Selected network" value={selectedNetworkId ?? ''} onChange={(event) => selectNetwork(event.target.value)}><option value="" disabled>Choose network</option>{inventory.networks.map((network) => <option key={network.network_id} value={network.network_id}>{network.name}</option>)}</select></label> : null}
          <button className="refresh-button" type="button" onClick={() => void refresh()} disabled={inventoryPending} aria-label="Refresh controller inventory"><RefreshCw aria-hidden="true" size={15} /></button>
          {session ? <div className="administrator-identity" aria-label="Signed in administrator"><strong>{session.username}</strong><span>{session.role}</span></div> : null}
          <button className="session-refresh-button" type="button" onClick={() => void handleRotation()} disabled={authPending}>{rotationPending ? 'Refreshing…' : 'Refresh session'}</button>
          <button className="sign-out-button" type="button" onClick={() => void handleSignOut()} disabled={authPending}>{signOutPending ? 'Signing out…' : 'Sign out'}</button>
        </div>
      </header>
      {authError ? <div className="session-error" role="alert">{authError}</div> : null}
      <main className="page-content"><Outlet /></main>
    </div>
  </div>
}
