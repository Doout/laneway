import { TwingatePage } from './pages/integrations/TwingatePage'
import { Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { ControllerAppShell } from './components/ControllerAppShell'
import { ThemeProvider } from './components/Theme'
import { AccessDeniedPage, CheckingSession, InventoryUnavailablePage, LoadingInventory, NotFoundPage, SelectNetworkPage } from './components/RouteFeedback'
import { isNetworkScopedAdministratorPermission, useControlPlane, type AdministratorPermission } from './lib/control-plane'
import { AuthenticationUnavailablePage, SetupRequiredPage, SignInPage } from './pages/auth/SignInPage'
import {
  AccessDetailPage,
  AccessPage,
  AddNodePage,
  ApplicationInstallPage,
  ApplicationRegistrationConsentPage,
  ApplicationsPage,
  ApproveRoutePage,
  AuditPage,
  CreateAccessPage,
  CreateGrantPage,
  CreateRoutePage,
  CreateTeamPage,
  CreateUserPage,
  InfrastructurePage,
  NetworkPage,
  NodeCapabilitiesPage,
  NodeDetailPage,
  NodeRevokePage,
  NetworksPage,
  OverviewPage,
  RelayPage,
  RouteDetailPage,
  RoutesPage,
  SecurityPage,
  TokenPage,
  TeamDetailPage,
  TeamsPage,
  UserDetailPage,
  UserEnrollmentPage,
  UsersPage,
} from './pages/live'

function Landing() {
  const { authState } = useControlPlane()
  if (authState === 'authenticated') return <Navigate to="/overview" replace />
  if (authState === 'checking') return <CheckingSession />
  if (authState === 'bootstrap_required') return <Navigate to="/setup" replace />
  if (authState === 'unavailable') return <AuthenticationUnavailablePage />
  return <Navigate to="/sign-in" replace />
}

function RequireSession() {
  const { authState } = useControlPlane()
  const location = useLocation()
  if (authState === 'checking') return <CheckingSession />
  if (authState === 'bootstrap_required') return <Navigate to="/setup" replace />
  if (authState === 'unavailable') return <AuthenticationUnavailablePage />
  return authState === 'authenticated' ? <Outlet /> : <Navigate to="/sign-in" replace state={{ from: location.pathname + location.search + location.hash }} />
}

function RequirePermission({ permission }: { permission: AdministratorPermission }) {
  const { inventory, inventoryError, hasPermission } = useControlPlane()
  if (!hasPermission(permission)) return <AccessDeniedPage />
  if (!isNetworkScopedAdministratorPermission(permission)) return <Outlet />
  if (!hasPermission('network.list')) return <AccessDeniedPage />
  if (!inventory) return inventoryError ? <InventoryUnavailablePage /> : <LoadingInventory />
  const networkId = inventory.network?.network_id
  if (!networkId && inventory.networks.length > 1) return <SelectNetworkPage />
  return networkId && hasPermission(permission, networkId) ? <Outlet /> : <AccessDeniedPage />
}

function RequireAuditPermission() {
  const { inventory, inventoryError, hasPermission } = useControlPlane()
  if (hasPermission('audit.read_global')) return <Outlet />
  if (!hasPermission('audit.read')) return <AccessDeniedPage />
  if (!inventory) return inventoryError ? <InventoryUnavailablePage /> : <LoadingInventory />
  const networkId = inventory.network?.network_id
  if (!networkId && inventory.networks.length > 1) return <SelectNetworkPage />
  return networkId && hasPermission('audit.read', networkId) ? <Outlet /> : <AccessDeniedPage />
}

function RequireAnyPermission({ permissions }: { permissions: AdministratorPermission[] }) {
  const { hasPermission } = useControlPlane()
  return permissions.some((permission) => hasPermission(permission)) ? <Outlet /> : <AccessDeniedPage />
}

export function App() {
  return <ThemeProvider><Routes>
    <Route index element={<Landing />} />
    <Route path="/sign-in" element={<SignInPage />} />
    <Route path="/setup" element={<SetupRequiredPage />} />
    <Route element={<RequireSession />}><Route element={<ControllerAppShell />}>
      <Route element={<RequirePermission permission="application.manage" />}><Route path="/applications/consent" element={<ApplicationRegistrationConsentPage />} /></Route>
      <Route element={<RequireAnyPermission permissions={['application_installation.manage']} />}><Route path="/applications/install" element={<ApplicationInstallPage />} /></Route>
      <Route element={<RequireAnyPermission permissions={['application.read', 'application_installation.read']} />}><Route path="/applications" element={<ApplicationsPage />} /></Route>
      <Route element={<RequirePermission permission="network.list" />}><Route path="/overview" element={<OverviewPage />} /><Route path="/infrastructure" element={<InfrastructurePage />} /></Route>
      <Route element={<RequirePermission permission="node.read" />}><Route path="/networks" element={<NetworksPage />} /><Route path="/nodes" element={<Navigate to="/networks" replace />} /><Route path="/nodes/:nodeId" element={<NodeDetailPage />} /></Route>
      <Route element={<RequirePermission permission="acl.read" />}><Route path="/users" element={<UsersPage />} /><Route path="/users/:userId" element={<UserDetailPage />} /><Route path="/teams" element={<TeamsPage />} /><Route path="/teams/:teamId" element={<TeamDetailPage />} /></Route>
      <Route element={<RequirePermission permission="enrollment.issue" />}><Route path="/nodes/new" element={<AddNodePage />} /><Route path="/nodes/new/token" element={<TokenPage />} /><Route path="/users/:userId/enroll" element={<UserEnrollmentPage />} /><Route path="/users/:userId/enroll/token" element={<TokenPage user />} /></Route>
      <Route element={<RequirePermission permission="node.manage" />}><Route path="/nodes/:nodeId/capabilities" element={<NodeCapabilitiesPage />} /><Route path="/nodes/:nodeId/revoke" element={<NodeRevokePage />} /></Route>
      <Route element={<RequirePermission permission="route.read" />}><Route path="/routes" element={<RoutesPage />} /><Route path="/routes/:routeId" element={<RouteDetailPage />} /></Route>
      <Route element={<RequirePermission permission="route.manage" />}><Route path="/routes/new" element={<CreateRoutePage />} /><Route path="/routes/:routeId/approve" element={<ApproveRoutePage />} /></Route>
      <Route element={<RequirePermission permission="acl.read" />}><Route path="/access" element={<AccessPage />} /><Route path="/access/:ruleId" element={<AccessDetailPage />} /></Route>
      <Route element={<RequirePermission permission="acl.manage" />}><Route path="/access/new" element={<CreateAccessPage />} /><Route path="/users/new" element={<CreateUserPage />} /><Route path="/teams/new" element={<CreateTeamPage />} /><Route path="/users/:userId/grants/new" element={<CreateGrantPage subjectKind="user" />} /><Route path="/teams/:teamId/grants/new" element={<CreateGrantPage subjectKind="team" />} /></Route>
      <Route element={<RequirePermission permission="network.read" />}><Route path="/infrastructure/networks/:networkId" element={<NetworkPage />} /></Route>
      <Route element={<RequirePermission permission="relay.read" />}><Route path="/infrastructure/relays/:relayId" element={<RelayPage />} /></Route>
      <Route element={<RequirePermission permission="relay.manage" />}><Route path="/infrastructure/relays/new" element={<RelayPage />} /></Route>
      <Route element={<RequirePermission permission="certificate.read" />}><Route path="/security" element={<SecurityPage />} /></Route>
      <Route element={<RequirePermission permission="integration.manage" />}>
        <Route path="/infrastructure/integrations/twingate" element={<TwingatePage />} />
        <Route path="/integrations/twingate" element={<Navigate to="/infrastructure/integrations/twingate" replace />} />
      </Route>
      <Route element={<RequireAuditPermission />}><Route path="/audit" element={<AuditPage />} /></Route>
      <Route path="*" element={<NotFoundPage />} />
    </Route></Route>
  </Routes></ThemeProvider>
}
