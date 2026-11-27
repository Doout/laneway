import { Link, useLocation } from 'react-router-dom'

const workspaceLabels: Record<string, string> = {
  overview: 'Overview', networks: 'Networks', nodes: 'Nodes', users: 'Users', teams: 'Teams',
  routes: 'Routes', access: 'Access', infrastructure: 'Infrastructure', applications: 'Applications',
  security: 'Security', audit: 'Audit',
}

const viewLabels: Record<string, string> = {
  new: 'Create', capabilities: 'Capabilities', revoke: 'Revoke node', approve: 'Review route',
  edit: 'Edit', enroll: 'Enrollment', token: 'Enrollment token', consent: 'Review application',
  install: 'Connect application', twingate: 'Twingate',
}

export function WorkspaceBreadcrumbs({ live = false }: { live?: boolean }) {
  const { pathname, search } = useLocation()
  const [workspace = 'overview', ...rest] = pathname.split('/').filter(Boolean)
  const workspaceLabel = workspaceLabels[workspace]
  const listUrl = live && workspace === 'nodes' ? '/networks?view=nodes' : '/' + workspace
  const last = rest.at(-1)
  const view = workspace === 'networks' ? new URLSearchParams(search).get('view') : null
  const subview = view === 'nodes' ? 'Nodes' : view === 'map' ? 'Map' : undefined
  const detail = last ? viewLabels[last] ?? 'Details' : subview

  return <nav className={last && workspaceLabel ? 'breadcrumbs breadcrumbs--nested' : 'breadcrumbs'} aria-label="Breadcrumb">
    <Link to="/overview">Laneway</Link>
    <span aria-hidden="true">/</span>
    {detail && workspaceLabel && <>
      <Link to={listUrl} aria-label={`Back to ${workspaceLabel}`}>{workspaceLabel}</Link>
      <span aria-hidden="true">/</span>
    </>}
    <span aria-current="page">{workspaceLabel ? detail ?? workspaceLabel : 'Page not found'}</span>
  </nav>
}
