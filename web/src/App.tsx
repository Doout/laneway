import { Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { Button, PageHeader } from './components/ui'
import { AccessRuleDetailPage, AccessRuleFormPage, AccessRulesPage } from './pages/access'
import { AuditPage } from './pages/audit/AuditPage'
import { SignInPage } from './pages/auth/SignInPage'
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
import { useControlPlane } from './lib/control-plane'

function RequireControllerSession() {
  const { authenticated, sessionPending } = useControlPlane()
  const location = useLocation()
  if (sessionPending) return <main className="auth-page"><p role="status">Restoring controller session…</p></main>
  return authenticated ? <Outlet /> : <Navigate to="/sign-in" replace state={{ from: location.pathname + location.search }} />
}

function NotFoundPage() {
  return <PageHeader title="Page not found" action={<Button to="/overview" variant="primary">Return to overview</Button>} />
}

export function App() {
  return (
    <Routes>
      <Route index element={<Navigate to="/sign-in" replace />} />
      <Route path="/sign-in" element={<SignInPage />} />

      <Route element={<RequireControllerSession />}>
        <Route element={<AppShell />}>
          <Route path="/overview" element={<OverviewPage />} />

        <Route path="/nodes" element={<NodesListPage />} />
        <Route path="/nodes/new" element={<AddNodePage />} />
        <Route path="/nodes/new/token" element={<NodeTokenPage />} />
        <Route path="/nodes/:nodeId" element={<NodeDetailPage />} />
        <Route path="/nodes/:nodeId/capabilities" element={<NodeCapabilitiesPage />} />
        <Route path="/nodes/:nodeId/revoke" element={<NodeRevokePage />} />

        <Route path="/users" element={<UsersListPage />} />
        <Route path="/users/new" element={<IssueUserAccessPage />} />
        <Route path="/users/new/token" element={<UserTokenPage />} />
        <Route path="/users/:userId" element={<UserDetailPage />} />

        <Route path="/routes" element={<RoutesListPage />} />
        <Route path="/routes/new" element={<CreateRoutePage />} />
        <Route path="/routes/:routeId/approve" element={<RouteApprovalPage />} />
        <Route path="/routes/:routeId" element={<RouteDetailPage />} />

        <Route path="/access" element={<AccessRulesPage />} />
        <Route path="/access/new" element={<AccessRuleFormPage />} />
        <Route path="/access/:ruleId/edit" element={<AccessRuleFormPage />} />
        <Route path="/access/:ruleId" element={<AccessRuleDetailPage />} />

        <Route path="/infrastructure" element={<InfrastructurePage />} />
        <Route path="/infrastructure/networks/:networkId" element={<NetworkDetailPage />} />
        <Route path="/infrastructure/relays/new" element={<RelayPage />} />
        <Route path="/infrastructure/relays/:relayId" element={<RelayPage />} />

        <Route path="/security" element={<SecurityPage />} />
        <Route path="/audit" element={<AuditPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
    </Routes>
  )
}
