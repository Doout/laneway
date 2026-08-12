import { Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { Button, PageHeader } from './components/ui'
import { AccessRuleDetailPage, AccessRuleFormPage, AccessRulesPage } from './pages/access'
import { AuditPage } from './pages/audit/AuditPage'
import { AuthenticationUnavailablePage, SetupRequiredPage, SignInPage } from './pages/auth/SignInPage'
import { InfrastructurePage } from './pages/infrastructure/InfrastructurePage'
import { NetworkDetailPage } from './pages/infrastructure/NetworkDetailPage'
import { RelayPage } from './pages/infrastructure/RelayPage'
import {
  AddNodePage,
  NodeCapabilitiesPage,
  NodeDetailPage,
  NodeRevokePage,
  NodesListPage,
  NodeTokenPage,
} from './pages/nodes'
import { OverviewPage } from './pages/overview/OverviewPage'
import { CreateRoutePage, RouteApprovalPage, RouteDetailPage, RoutesListPage } from './pages/routes'
import { SecurityPage } from './pages/security/SecurityPage'
import { IssueUserAccessPage, UserDetailPage, UsersListPage, UserTokenPage } from './pages/users'
import { isNetworkScopedAdministratorPermission, useControlPlane, type AdministratorPermission } from './lib/control-plane'

function LoadingAuthentication() {
  return <main className="auth-page"><p role="status">Checking administrator session…</p></main>
}

function LandingPage() {
  const { authState, live } = useControlPlane()
  if (!live || authState === 'authenticated') return <Navigate to="/overview" replace />
  if (authState === 'checking') return <LoadingAuthentication />
  if (authState === 'bootstrap_required') return <Navigate to="/setup" replace />
  if (authState === 'unavailable') return <AuthenticationUnavailablePage />
  return <Navigate to="/sign-in" replace />
}

function RequireControllerSession() {
  const { authState, authenticated, live } = useControlPlane()
  const location = useLocation()
  if (!live) return <Outlet />
  if (authState === 'checking') return <LoadingAuthentication />
  if (authState === 'bootstrap_required') return <Navigate to="/setup" replace />
  if (authState === 'unavailable') return <AuthenticationUnavailablePage />
  return authenticated
    ? <Outlet />
    : <Navigate to="/sign-in" replace state={{ from: location.pathname + location.search + location.hash }} />
}

function AccessDeniedPage() {
  return <PageHeader title="Access denied" action={<Button to="/overview" variant="primary">Return to overview</Button>} />
}

function RequirePermission({ permission }: { permission: AdministratorPermission }) {
  const { live, inventory, inventoryError, hasPermission } = useControlPlane()
  if (!hasPermission(permission)) return <AccessDeniedPage />
  if (!live || !isNetworkScopedAdministratorPermission(permission)) return <Outlet />
  if (!hasPermission('network.list')) return <AccessDeniedPage />
  if (!inventory) {
    return inventoryError
      ? <PageHeader title="Inventory unavailable" action={<Button to="/overview" variant="primary">Return to overview</Button>} />
      : <main className="auth-page"><p role="status">Loading authorized inventory…</p></main>
  }
  const networkId = inventory.network?.network_id
  return networkId && hasPermission(permission, networkId) ? <Outlet /> : <AccessDeniedPage />
}

function NotFoundPage() {
  return <PageHeader title="Page not found" action={<Button to="/overview" variant="primary">Return to overview</Button>} />
}

export function App() {
  return <Routes>
    <Route index element={<LandingPage />} />
    <Route path="/sign-in" element={<SignInPage />} />
    <Route path="/setup" element={<SetupRequiredPage />} />

    <Route element={<RequireControllerSession />}>
      <Route element={<AppShell />}>
        <Route element={<RequirePermission permission="network.list" />}>
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/infrastructure" element={<InfrastructurePage />} />
        </Route>

        <Route element={<RequirePermission permission="node.read" />}>
          <Route path="/nodes" element={<NodesListPage />} />
          <Route path="/nodes/:nodeId" element={<NodeDetailPage />} />
          <Route path="/users" element={<UsersListPage />} />
          <Route path="/users/:userId" element={<UserDetailPage />} />
        </Route>
        <Route element={<RequirePermission permission="enrollment.issue" />}>
          <Route path="/nodes/new" element={<AddNodePage />} />
          <Route path="/nodes/new/token" element={<NodeTokenPage />} />
          <Route path="/users/new" element={<IssueUserAccessPage />} />
          <Route path="/users/new/token" element={<UserTokenPage />} />
        </Route>
        <Route element={<RequirePermission permission="node.manage" />}>
          <Route path="/nodes/:nodeId/capabilities" element={<NodeCapabilitiesPage />} />
          <Route path="/nodes/:nodeId/revoke" element={<NodeRevokePage />} />
        </Route>

        <Route element={<RequirePermission permission="route.read" />}>
          <Route path="/routes" element={<RoutesListPage />} />
          <Route path="/routes/:routeId" element={<RouteDetailPage />} />
        </Route>
        <Route element={<RequirePermission permission="route.manage" />}>
          <Route path="/routes/new" element={<CreateRoutePage />} />
          <Route path="/routes/:routeId/approve" element={<RouteApprovalPage />} />
        </Route>

        <Route element={<RequirePermission permission="acl.read" />}>
          <Route path="/access" element={<AccessRulesPage />} />
          <Route path="/access/:ruleId" element={<AccessRuleDetailPage />} />
        </Route>
        <Route element={<RequirePermission permission="acl.manage" />}>
          <Route path="/access/new" element={<AccessRuleFormPage />} />
          <Route path="/access/:ruleId/edit" element={<AccessRuleFormPage />} />
        </Route>

        <Route element={<RequirePermission permission="network.read" />}>
          <Route path="/infrastructure/networks/:networkId" element={<NetworkDetailPage />} />
        </Route>
        <Route element={<RequirePermission permission="relay.manage" />}>
          <Route path="/infrastructure/relays/new" element={<RelayPage />} />
        </Route>
        <Route element={<RequirePermission permission="relay.read" />}>
          <Route path="/infrastructure/relays/:relayId" element={<RelayPage />} />
        </Route>

        <Route element={<RequirePermission permission="certificate.read" />}>
          <Route path="/security" element={<SecurityPage />} />
        </Route>
        <Route element={<RequirePermission permission="audit.read" />}>
          <Route path="/audit" element={<AuditPage />} />
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Route>
  </Routes>
}
