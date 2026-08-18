import { Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { LiveAppShell } from './components/LiveAppShell'
import { Button, PageHeader } from './components/ui'
import { isNetworkScopedAdministratorPermission, useControlPlane, type AdministratorPermission } from './lib/control-plane'
import { AuthenticationUnavailablePage, SetupRequiredPage, SignInPage } from './pages/auth/SignInPage'
import {
  LiveAccessDetailPage,
  LiveAccessPage,
  LiveAddNodePage,
  LiveApproveRoutePage,
  LiveAuditPage,
  LiveCreateAccessPage,
  LiveCreateGrantPage,
  LiveCreateRoutePage,
  LiveCreateTeamPage,
  LiveCreateUserPage,
  LiveInfrastructurePage,
  LiveNetworkPage,
  LiveNodeCapabilitiesPage,
  LiveNodeDetailPage,
  LiveNodeRevokePage,
  LiveNodesPage,
  LiveOverviewPage,
  LiveRelayPage,
  LiveRouteDetailPage,
  LiveRoutesPage,
  LiveSecurityPage,
  LiveTokenPage,
  LiveTeamDetailPage,
  LiveTeamsPage,
  LiveUserDetailPage,
  LiveUserEnrollmentPage,
  LiveUsersPage,
} from './pages/live/LivePages'

function Loading({ children = 'Checking administrator session…' }: { children?: string }) {
  return <main className="auth-page"><p role="status">{children}</p></main>
}

function Landing() {
  const { authState } = useControlPlane()
  if (authState === 'authenticated') return <Navigate to="/overview" replace />
  if (authState === 'checking') return <Loading />
  if (authState === 'bootstrap_required') return <Navigate to="/setup" replace />
  if (authState === 'unavailable') return <AuthenticationUnavailablePage />
  return <Navigate to="/sign-in" replace />
}

function RequireSession() {
  const { authState } = useControlPlane()
  const location = useLocation()
  if (authState === 'checking') return <Loading />
  if (authState === 'bootstrap_required') return <Navigate to="/setup" replace />
  if (authState === 'unavailable') return <AuthenticationUnavailablePage />
  return authState === 'authenticated' ? <Outlet /> : <Navigate to="/sign-in" replace state={{ from: location.pathname + location.search + location.hash }} />
}

function Denied() { return <PageHeader title="Access denied" action={<Button to="/overview" variant="primary">Overview</Button>} /> }
function SelectNetwork() { return <PageHeader title="Select a network" action={<Button to="/overview" variant="primary">Overview</Button>} /> }

function RequirePermission({ permission }: { permission: AdministratorPermission }) {
  const { inventory, inventoryError, hasPermission } = useControlPlane()
  if (!hasPermission(permission)) return <Denied />
  if (!isNetworkScopedAdministratorPermission(permission)) return <Outlet />
  if (!hasPermission('network.list')) return <Denied />
  if (!inventory) return inventoryError ? <PageHeader title="Inventory unavailable" /> : <Loading>Loading authorized inventory…</Loading>
  const networkId = inventory.network?.network_id
  if (!networkId && inventory.networks.length > 1) return <SelectNetwork />
  return networkId && hasPermission(permission, networkId) ? <Outlet /> : <Denied />
}

function RequireAuditPermission() {
  const { inventory, inventoryError, hasPermission } = useControlPlane()
  if (hasPermission('audit.read_global')) return <Outlet />
  if (!hasPermission('audit.read')) return <Denied />
  if (!inventory) return inventoryError ? <PageHeader title="Inventory unavailable" /> : <Loading>Loading authorized inventory…</Loading>
  const networkId = inventory.network?.network_id
  if (!networkId && inventory.networks.length > 1) return <SelectNetwork />
  return networkId && hasPermission('audit.read', networkId) ? <Outlet /> : <Denied />
}

export function App() {
  return <Routes>
    <Route index element={<Landing />} />
    <Route path="/sign-in" element={<SignInPage />} />
    <Route path="/setup" element={<SetupRequiredPage />} />
    <Route element={<RequireSession />}><Route element={<LiveAppShell />}>
      <Route element={<RequirePermission permission="network.list" />}><Route path="/overview" element={<LiveOverviewPage />} /><Route path="/infrastructure" element={<LiveInfrastructurePage />} /></Route>
      <Route element={<RequirePermission permission="node.read" />}><Route path="/nodes" element={<LiveNodesPage />} /><Route path="/nodes/:nodeId" element={<LiveNodeDetailPage />} /></Route>
      <Route element={<RequirePermission permission="acl.read" />}><Route path="/users" element={<LiveUsersPage />} /><Route path="/users/:userId" element={<LiveUserDetailPage />} /><Route path="/teams" element={<LiveTeamsPage />} /><Route path="/teams/:teamId" element={<LiveTeamDetailPage />} /></Route>
      <Route element={<RequirePermission permission="enrollment.issue" />}><Route path="/nodes/new" element={<LiveAddNodePage />} /><Route path="/nodes/new/token" element={<LiveTokenPage />} /><Route path="/users/:userId/enroll" element={<LiveUserEnrollmentPage />} /><Route path="/users/:userId/enroll/token" element={<LiveTokenPage user />} /></Route>
      <Route element={<RequirePermission permission="node.manage" />}><Route path="/nodes/:nodeId/capabilities" element={<LiveNodeCapabilitiesPage />} /><Route path="/nodes/:nodeId/revoke" element={<LiveNodeRevokePage />} /></Route>
      <Route element={<RequirePermission permission="route.read" />}><Route path="/routes" element={<LiveRoutesPage />} /><Route path="/routes/:routeId" element={<LiveRouteDetailPage />} /></Route>
      <Route element={<RequirePermission permission="route.manage" />}><Route path="/routes/new" element={<LiveCreateRoutePage />} /><Route path="/routes/:routeId/approve" element={<LiveApproveRoutePage />} /></Route>
      <Route element={<RequirePermission permission="acl.read" />}><Route path="/access" element={<LiveAccessPage />} /><Route path="/access/:ruleId" element={<LiveAccessDetailPage />} /></Route>
      <Route element={<RequirePermission permission="acl.manage" />}><Route path="/access/new" element={<LiveCreateAccessPage />} /><Route path="/users/new" element={<LiveCreateUserPage />} /><Route path="/teams/new" element={<LiveCreateTeamPage />} /><Route path="/users/:userId/grants/new" element={<LiveCreateGrantPage subjectKind="user" />} /><Route path="/teams/:teamId/grants/new" element={<LiveCreateGrantPage subjectKind="team" />} /></Route>
      <Route element={<RequirePermission permission="network.read" />}><Route path="/infrastructure/networks/:networkId" element={<LiveNetworkPage />} /></Route>
      <Route element={<RequirePermission permission="relay.read" />}><Route path="/infrastructure/relays/:relayId" element={<LiveRelayPage />} /></Route>
      <Route element={<RequirePermission permission="relay.manage" />}><Route path="/infrastructure/relays/new" element={<LiveRelayPage />} /></Route>
      <Route element={<RequirePermission permission="certificate.read" />}><Route path="/security" element={<LiveSecurityPage />} /></Route>
      <Route element={<RequireAuditPermission />}><Route path="/audit" element={<LiveAuditPage />} /></Route>
      <Route path="*" element={<PageHeader title="Page not found" action={<Button to="/overview">Overview</Button>} />} />
    </Route></Route>
  </Routes>
}
