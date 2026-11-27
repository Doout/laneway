import {
  LayoutDashboard,
  MonitorDot,
  Network,
  RadioTower,
  RefreshCw,
  Route,
  ScrollText,
  ShieldCheck,
  Users,
} from 'lucide-react'
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import clsx from 'clsx'
import { isNetworkScopedAdministratorPermission, useControlPlane, type AdministratorPermission } from '../lib/control-plane'
import { isPendingControllerRoute } from '../lib/live-records'
import { ThemeToggle } from './Theme'
import { MobileNavigation } from './MobileNavigation'
import { BrandMark } from './BrandMark'
import { WorkspaceBreadcrumbs } from './WorkspaceBreadcrumbs'

const navigation = [
  {
    label: 'Control',
    items: [
      { label: 'Overview', to: '/overview', icon: LayoutDashboard, permission: 'network.list' },
      { label: 'Nodes', to: '/nodes', icon: MonitorDot, permission: 'node.read' },
      { label: 'Users', to: '/users', icon: Users, permission: 'node.read' },
    ],
  },
  {
    label: 'Connectivity',
    items: [
      { label: 'Routes', to: '/routes', icon: Route, permission: 'route.read' },
      { label: 'Infrastructure', to: '/infrastructure', icon: Network, permission: 'network.list' },
    ],
  },
  {
    label: 'Governance',
    items: [
      { label: 'Access', to: '/access', icon: ShieldCheck, permission: 'acl.read' },
      { label: 'Security', to: '/security', icon: RadioTower, permission: 'certificate.read' },
      { label: 'Audit', to: '/audit', icon: ScrollText, permission: 'audit.read' },
    ],
  },
]

export function AppShell() {
  const navigate = useNavigate()
  const { live, session, inventory, inventoryError, inventoryPending, authPending, authError, hasPermission, refresh, signOut } = useControlPlane()
  const networkName = inventory?.network?.name
  const epoch = inventory?.network?.configuration_epoch
  const pendingRoutes = live ? inventory?.routes.filter(isPendingControllerRoute).length ?? 0 : 2
  const controllerStatus = inventoryError
    ? 'Inventory unavailable'
    : inventory
      ? inventoryPending ? 'Refreshing inventory…' : 'Inventory loaded'
      : 'Loading inventory…'

  async function handleSignOut() {
    if (await signOut()) navigate('/sign-in', { replace: true })
  }

  const navigationMenu = <nav className="sidebar-nav" aria-label="Primary navigation">
    {navigation.map(group => {
      const visibleItems = group.items.filter(item => {
        const permission = item.permission as AdministratorPermission
        if (!live) return true
        if (!isNetworkScopedAdministratorPermission(permission)) return hasPermission(permission)
        const networkId = inventory?.network?.network_id
        return Boolean(networkId && hasPermission(permission, networkId))
      })
      if (!visibleItems.length) return null
      return <section className="sidebar-nav__group" key={group.label}>
        <h2>{group.label}</h2>
        {visibleItems.map(item => {
          const Icon = item.icon
          const accessibleLabel = item.to === '/routes' && pendingRoutes > 0
            ? `${item.label}, ${pendingRoutes} routes need review`
            : item.label
          return <NavLink aria-label={accessibleLabel} title={item.label} key={item.to} to={item.to} className={({ isActive }) => clsx('sidebar-nav__item', isActive && 'is-active')}>
            <Icon aria-hidden="true" size={17} />
            <span>{item.label}</span>
            {item.to === '/routes' && pendingRoutes > 0 ? <em aria-label={`${pendingRoutes} routes need review`}>{pendingRoutes}</em> : null}
          </NavLink>
        })}
      </section>
    })}
  </nav>

  return <div className="app-shell">
    <aside className="sidebar">
      <Link to="/overview" className="wordmark" aria-label="Laneway overview"><BrandMark /><span>Laneway</span></Link>
      {navigationMenu}
      {live && networkName ? <div className="sidebar-environment">
        <span className="sidebar-environment__icon"><Network aria-hidden="true" size={17} /></span>
        <span><strong>{networkName}</strong></span>
      </div> : null}
    </aside>

    <div className="app-frame">
      <header className="command-bar">
        <MobileNavigation>{navigationMenu}</MobileNavigation>
        <WorkspaceBreadcrumbs />
        <div className="command-bar__tools">
          {!live ? <div className="demo-notice" role="note" aria-label="Demo data notice"><strong>Demo data</strong></div> : null}
          {live ? <button className="refresh-button" type="button" onClick={() => void refresh()} disabled={inventoryPending} aria-label="Refresh controller inventory"><RefreshCw aria-hidden="true" size={15} /></button> : null}
          <ThemeToggle />
          {live && session ? <div className="administrator-identity" aria-label="Signed in administrator"><strong>{session.username}</strong><span>{session.role}</span></div> : null}
          {live ? <button className="sign-out-button" type="button" onClick={() => void handleSignOut()} disabled={authPending}>{authPending ? 'Signing out…' : 'Sign out'}</button> : null}
        </div>
      </header>

      {live && authError ? <div className="session-error" role="alert">{authError}</div> : null}

      {live && inventoryError ? <div className="demo-notice demo-notice--danger" role="alert"><strong>Console unavailable</strong><span>{inventoryError}</span></div> : null}

      <main className="page">
        {live && inventoryError
          ? null
          : live && (inventoryPending || !inventory)
            ? <p role="status">Loading inventory…</p>
            : <Outlet />}
      </main>

      {live ? <footer className="system-bar">
        <span>{controllerStatus}</span>
        {epoch !== undefined ? <span>Configuration epoch: <strong>{epoch}</strong></span> : null}
      </footer> : null}
    </div>
  </div>
}
