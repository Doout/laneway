import { useCallback, useEffect, useMemo, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { AppWindow, Check, ExternalLink, KeyRound, Link2, Network, ShieldCheck, Trash2, X } from 'lucide-react'
import { Button, DataTable, EmptyState, Field, FilterSelect, PageHeader, Section, Status, TokenBox } from '../../components/ui'
import { useControlPlane, type AdministratorPermission, type ControllerNetwork } from '../../lib/control-plane'
import { ErrorMessage } from './shared'
import './applications.css'

type ApplicationManifest = {
  name: string
  homepage_uri: string
  setup_uri: string
  redirect_uris: string[]
  scopes: string[]
  token_endpoint_auth_method: 'client_secret_basic'
}

type RegisteredApplication = ApplicationManifest & {
  application_id: string
  client_id: string
  enabled: boolean
  created_at_unix_seconds: number
  updated_at_unix_seconds: number
}

type ApplicationInstallation = {
  installation_id: string
  application_id: string
  network_id: string
  service_principal_id: string
  scopes: string[]
  enabled: boolean
  created_at_unix_seconds: number
  updated_at_unix_seconds: number
}

type RegistrationRequest = {
  request_id: string
  manifest: ApplicationManifest
  expires_at_unix_seconds: number
}

type AuthorizationRequest = {
  request_id: string
  application: RegisteredApplication
  redirect_uri: string
  scopes: string[]
  expires_at_unix_seconds: number
}

type RedirectResponse = { redirect_uri: string }

const requestPattern = /^[0-9a-f]{32}$/
const scopeCopy: Record<string, { label: string; detail: string }> = {
  'network.read': { label: 'View network', detail: 'See the network name and address range.' },
  'node.read': { label: 'View nodes', detail: 'See nodes and whether they are connected.' },
  'enrollment.issue': { label: 'Add nodes', detail: 'Create short-lived credentials for new nodes.' },
  'route.read': { label: 'View routes', detail: 'See routes in this network.' },
  'route.manage': { label: 'Manage routes', detail: 'Add or change routes through selected nodes.' },
}
const scopePermissions: Record<string, AdministratorPermission> = {
  'network.read': 'network.read',
  'node.read': 'node.read',
  'enrollment.issue': 'enrollment.issue',
  'route.read': 'route.read',
  'route.manage': 'route.manage',
}

function requestID(search: string) {
  const value = new URLSearchParams(search).get('request') ?? ''
  return requestPattern.test(value) ? value : ''
}

function ScopeList({ scopes, selected, disabled, onChange }: { scopes: string[]; selected?: string[]; disabled?: string[]; onChange?: (scope: string, checked: boolean) => void }) {
  return <ul className="application-scopes">{scopes.map((scope) => {
    const isSelectable = Boolean(onChange)
    const isSelected = selected?.includes(scope) ?? true
    const isDisabled = disabled?.includes(scope) ?? false
    const content = <><span className="application-scope-check">{isSelectable ? <input aria-label={scopeCopy[scope]?.label ?? scope} type="checkbox" checked={isSelected} disabled={isDisabled} onChange={(event) => onChange?.(scope, event.target.checked)} /> : <Check aria-hidden="true" size={15} />}</span><div><strong>{scopeCopy[scope]?.label ?? scope}</strong><small>{isDisabled ? 'Your account cannot grant this permission on the selected network.' : scopeCopy[scope]?.detail ?? 'Access requested by this application.'}</small></div></>
    return <li key={scope} className={isDisabled ? 'disabled' : undefined}>{isSelectable ? <label className="application-scope-row">{content}</label> : <div className="application-scope-row">{content}</div>}</li>
  })}</ul>
}

function callbackHost(uri: string) {
  try { return new URL(uri).host } catch { return uri }
}

function BreakableURL({ value }: { value: string }) {
  try {
    const url = new URL(value)
    const remainder = `${url.pathname}${url.search}${url.hash}`
    return <code title={value} className="application-registration-url"><span>{url.origin}</span>{remainder !== '/' ? <><wbr /><span>{remainder}</span></> : null}</code>
  } catch {
    return <code title={value} className="application-registration-url">{value}</code>
  }
}

function navigateToCallback(uri: string) {
  window.location.assign(uri)
}

async function publicJSON<T>(path: string, signal: AbortSignal): Promise<T> {
  const response = await fetch(path, { headers: { Accept: 'application/json' }, credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal })
  if (!response.ok) throw new Error('This application request is unavailable or has expired.')
  return response.json() as Promise<T>
}

export function ApplicationRegistrationConsentPage() {
  const { request } = useControlPlane()
  const { search } = useLocation()
  const id = useMemo(() => requestID(search), [search])
  const [value, setValue] = useState<RegistrationRequest | null>(null)
  const [pending, setPending] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    if (!id) { setPending(false); setError('This registration request is invalid.'); return () => controller.abort() }
    request<RegistrationRequest>(`/v1/admin/application-registration-requests/${id}`, { signal: controller.signal })
      .then(setValue).catch((cause: unknown) => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Registration request unavailable.') })
      .finally(() => { if (!controller.signal.aborted) setPending(false) })
    return () => controller.abort()
  }, [id, request])

  async function decide(action: 'approve' | 'cancel') {
    if (!value) return
    setSubmitting(true); setError('')
    try {
      const response = await request<RedirectResponse>(`/v1/admin/application-registration-requests/${value.request_id}/${action}`, { method: 'POST' })
      navigateToCallback(response.redirect_uri)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The registration decision failed.')
      setSubmitting(false)
    }
  }

  if (pending) return <PageHeader title="Review application" description="Loading registration request…" />
  if (!value) return <><PageHeader title="Registration unavailable" /><ErrorMessage value={error} /></>
  const permissionCount = value.manifest.scopes.length
  const callbackCount = value.manifest.redirect_uris.length
  return <div className="application-consent-page application-registration-consent">
    <section className="application-registration-panel" aria-labelledby="application-registration-title">
      <header className="application-registration-header">
        <span className="application-registration-icon"><AppWindow aria-hidden="true" size={25} /></span>
        <div>
          <p>Application registration</p>
          <h1 id="application-registration-title">Register {value.manifest.name}?</h1>
          <a href={value.manifest.homepage_uri} target="_blank" rel="noreferrer">
            {callbackHost(value.manifest.homepage_uri)} <ExternalLink aria-hidden="true" size={13} />
          </a>
        </div>
      </header>

      <div className="application-registration-body">
        <section className="application-registration-permissions" aria-labelledby="application-permissions-title">
          <div className="application-registration-section-heading">
            <h2 id="application-permissions-title">Permissions it can request</h2>
            <span>{permissionCount}</span>
          </div>
          <ScopeList scopes={value.manifest.scopes} />
        </section>

        <aside className="application-registration-details" aria-labelledby="application-details-title">
          <h2 id="application-details-title">Connection details</h2>
          <dl>
            <div>
              <dt>Setup URL</dt>
              <dd><BreakableURL value={value.manifest.setup_uri} /></dd>
            </div>
            <div>
              <dt>OAuth redirect {callbackCount === 1 ? 'URL' : 'URLs'} <span>{callbackCount}</span></dt>
              <dd>
                <ul>{value.manifest.redirect_uris.map((uri) => <li key={uri}><BreakableURL value={uri} /></li>)}</ul>
              </dd>
            </div>
            <div>
              <dt>Client authentication</dt>
              <dd>Client secret and PKCE</dd>
            </div>
          </dl>
        </aside>
      </div>

      <ErrorMessage value={error} />
      <footer className="application-registration-footer">
        <div className="application-registration-boundary">
          <ShieldCheck aria-hidden="true" size={18} />
          <p>Registration does not give {value.manifest.name} network access. You choose a network and approve its permissions when you connect it.</p>
        </div>
        <div className="application-consent-actions">
          <Button variant="quiet" disabled={submitting} onClick={() => void decide('cancel')}><X size={16} />Cancel</Button>
          <Button variant="primary" disabled={submitting} onClick={() => void decide('approve')}><Check size={16} />Register application</Button>
        </div>
      </footer>
    </section>
  </div>
}

export function ApplicationInstallPage() {
  const { inventory, hasPermission, request } = useControlPlane()
  const { search } = useLocation()
  const id = useMemo(() => requestID(search), [search])
  const networks = (inventory?.networks ?? []).filter((network) => hasPermission('application_installation.manage', network.network_id))
  const [value, setValue] = useState<AuthorizationRequest | null>(null)
  const [networkID, setNetworkID] = useState('')
  const [grantedScopes, setGrantedScopes] = useState<string[]>([])
  const [pending, setPending] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    if (!id) { setPending(false); setError('This authorization request is invalid.'); return () => controller.abort() }
    publicJSON<AuthorizationRequest>(`/oauth/authorization-requests/${id}`, controller.signal)
      .then(setValue).catch((cause: unknown) => { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Authorization request unavailable.') })
      .finally(() => { if (!controller.signal.aborted) setPending(false) })
    return () => controller.abort()
  }, [id])

  useEffect(() => {
    if (!networkID && networks.length) setNetworkID(networks[0].network_id)
  }, [networkID, networks])

  const unavailableScopes = useMemo(() => value && networkID
    ? value.scopes.filter((scope) => !hasPermission(scopePermissions[scope], networkID))
    : [], [hasPermission, networkID, value])

  useEffect(() => {
    if (value && networkID) setGrantedScopes(value.scopes.filter((scope) => !unavailableScopes.includes(scope)))
  }, [networkID, unavailableScopes, value])

  function selectScope(scope: string, checked: boolean) {
    setGrantedScopes((current) => checked
      ? current.includes(scope) ? current : [...current, scope].sort()
      : current.filter((item) => item !== scope))
  }

  async function decide(action: 'approve' | 'cancel') {
    if (!value || !networkID) return
    setSubmitting(true); setError('')
    try {
      const response = await request<RedirectResponse>(`/v1/admin/networks/${networkID}/application-authorization-requests/${value.request_id}/${action}`, { method: 'POST', body: action === 'approve' ? { scopes: grantedScopes } : undefined })
      navigateToCallback(response.redirect_uri)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The authorization decision failed.')
      setSubmitting(false)
    }
  }

  if (pending) return <PageHeader title="Connect application" description="Loading authorization request…" />
  if (!value) return <><PageHeader title="Authorization unavailable" /><ErrorMessage value={error} /></>
  return <div className="application-consent-page">
    <PageHeader title={`Connect ${value.application.name}`} description="Choose the network this application can access." />
    <div className="application-consent-layout">
      <section className="application-consent-card">
        <Field label="Network"><select value={networkID} onChange={(event) => setNetworkID(event.target.value)} disabled={!networks.length}>{networks.length ? networks.map((network) => <option key={network.network_id} value={network.network_id}>{network.name} · {network.ipv4_pool}</option>) : <option value="">No manageable networks</option>}</select></Field>
        <h3>Requested access</h3><ScopeList scopes={value.scopes} selected={grantedScopes} disabled={unavailableScopes} onChange={selectScope} />
      </section>
      <aside className="application-consent-summary"><div className="application-consent-identity compact"><span><Link2 aria-hidden="true" size={21} /></span><div><h2>{value.application.name}</h2><small>{callbackHost(value.redirect_uri)}</small></div></div><p>This creates one service identity limited to the selected network and the access shown here.</p></aside>
    </div>
    <ErrorMessage value={error} />
    <div className="application-consent-actions"><Button variant="quiet" disabled={submitting || !networkID} onClick={() => void decide('cancel')}><X size={16} />Cancel</Button><Button variant="primary" disabled={submitting || !networkID || !grantedScopes.length} onClick={() => void decide('approve')}><ShieldCheck size={16} />Allow access</Button></div>
  </div>
}

export function ApplicationsPage() {
  const { inventory, hasPermission, request } = useControlPlane()
  const readableNetworks = (inventory?.networks ?? []).filter((network) => hasPermission('application_installation.read', network.network_id))
  const [networkID, setNetworkID] = useState('')
  const [applications, setApplications] = useState<RegisteredApplication[]>([])
  const [installations, setInstallations] = useState<ApplicationInstallation[]>([])
  const [secret, setSecret] = useState('')
  const [pending, setPending] = useState(true)
  const [error, setError] = useState('')
  const canReadApplications = hasPermission('application.read')
  const canManageApplications = hasPermission('application.manage')

  useEffect(() => {
    if (!networkID && readableNetworks.length) setNetworkID(inventory?.network && readableNetworks.some((item) => item.network_id === inventory.network?.network_id) ? inventory.network.network_id : readableNetworks[0].network_id)
  }, [inventory?.network, networkID, readableNetworks])

  const load = useCallback(async () => {
    setPending(true); setError('')
    try {
      const [applicationResponse, installationResponse] = await Promise.all([
        canReadApplications ? request<{ applications: RegisteredApplication[] }>('/v1/admin/applications?limit=500') : Promise.resolve({ applications: [] }),
        networkID ? request<{ application_installations: ApplicationInstallation[] }>(`/v1/admin/networks/${networkID}/application-installations?limit=100`) : Promise.resolve({ application_installations: [] }),
      ])
      setApplications(applicationResponse.applications)
      setInstallations(installationResponse.application_installations)
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Applications could not be loaded.') }
    finally { setPending(false) }
  }, [canReadApplications, networkID, request])

  useEffect(() => { void load() }, [load])

  async function rotate(application: RegisteredApplication) {
    if (!window.confirm(`Create a new client secret for ${application.name}? The current secret will stop working.`)) return
    try { const response = await request<{ client_secret: string }>(`/v1/admin/applications/${application.application_id}/client-secrets`, { method: 'POST' }); setSecret(response.client_secret) }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Client secret rotation failed.') }
  }

  async function disable(application: RegisteredApplication) {
    if (!window.confirm(`Disable ${application.name} and revoke all of its network access?`)) return
    try { await request(`/v1/admin/applications/${application.application_id}/disable`, { method: 'POST' }); await load() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Application removal failed.') }
  }

  async function remove(application: RegisteredApplication) {
    if (!window.confirm(`Delete ${application.name}? This permanently removes the registration. Audit records remain.`)) return
    try { await request(`/v1/admin/applications/${application.application_id}`, { method: 'DELETE' }); await load() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Application deletion failed.') }
  }

  async function revoke(installation: ApplicationInstallation) {
    if (!window.confirm('Remove this application from the selected network?')) return
    try { await request(`/v1/admin/application-installations/${installation.installation_id}`, { method: 'DELETE' }); await load() }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Application access removal failed.') }
  }

  const applicationsByID = new Map(applications.map((application) => [application.application_id, application]))
  return <div className="applications-page">
    <PageHeader title="Applications" description="Applications registered with Laneway and the networks they can access." />
    <ErrorMessage value={error} />
    {secret ? <div className="application-secret"><div><KeyRound aria-hidden="true" size={20} /><div><strong>Save this client secret now</strong><p>It will not be shown again.</p></div></div><TokenBox label="Client secret" value={secret} /><Button variant="quiet" onClick={() => setSecret('')}>Done</Button></div> : null}
    {canReadApplications ? <Section title="Registered applications" meta={pending ? 'Loading…' : `${applications.length} total`}>
      <DataTable columns={[
        { key: 'application', label: 'Application', render: (application: RegisteredApplication) => <span className="application-name"><span><AppWindow size={18} /></span><span><strong>{application.name}</strong><small>{callbackHost(application.homepage_uri)}</small></span></span> },
        { key: 'client', label: 'Client ID', render: (application: RegisteredApplication) => <code title={application.client_id}>{application.client_id}</code> },
        { key: 'access', label: 'Can request', render: (application: RegisteredApplication) => `${application.scopes.length} ${application.scopes.length === 1 ? 'permission' : 'permissions'}` },
        { key: 'state', label: 'State', render: (application: RegisteredApplication) => <Status tone={application.enabled ? 'positive' : 'muted'}>{application.enabled ? 'Enabled' : 'Disabled'}</Status> },
        { key: 'actions', label: '', align: 'end', render: (application: RegisteredApplication) => canManageApplications ? application.enabled ? <div className="button-row compact"><Button variant="quiet" onClick={() => void rotate(application)}><KeyRound size={14} />New secret</Button><Button variant="quiet" onClick={() => void disable(application)}><Trash2 size={14} />Disable</Button></div> : <Button variant="danger" onClick={() => void remove(application)}><Trash2 size={14} />Delete</Button> : null },
      ]} rows={applications} rowKey={(application) => application.application_id} empty={<EmptyState icon={<AppWindow />} title="No registered applications" description="Applications appear here after an owner approves registration." />} />
    </Section> : null}
    <Section title="Network access" meta={networkID ? `${installations.filter((item) => item.enabled).length} active` : undefined} action={readableNetworks.length ? <FilterSelect label="Network" value={networkID} onChange={setNetworkID}>{readableNetworks.map((network: ControllerNetwork) => <option key={network.network_id} value={network.network_id}>{network.name}</option>)}</FilterSelect> : undefined}>
      <DataTable columns={[
        { key: 'application', label: 'Application', render: (installation: ApplicationInstallation) => <span><strong>{applicationsByID.get(installation.application_id)?.name ?? 'Registered application'}</strong><small className="application-table-detail">{installation.application_id}</small></span> },
        { key: 'identity', label: 'Service identity', render: (installation: ApplicationInstallation) => <code title={installation.service_principal_id}>{installation.service_principal_id}</code> },
        { key: 'access', label: 'Granted access', render: (installation: ApplicationInstallation) => `${installation.scopes.length} ${installation.scopes.length === 1 ? 'permission' : 'permissions'}` },
        { key: 'state', label: 'State', render: (installation: ApplicationInstallation) => <Status tone={installation.enabled ? 'positive' : 'muted'}>{installation.enabled ? 'Connected' : 'Removed'}</Status> },
        { key: 'actions', label: '', align: 'end', render: (installation: ApplicationInstallation) => installation.enabled && hasPermission('application_installation.manage', installation.network_id) ? <Button variant="quiet" onClick={() => void revoke(installation)}>Remove</Button> : null },
      ]} rows={installations} rowKey={(installation) => installation.installation_id} empty={<EmptyState icon={<Network />} title={readableNetworks.length ? 'No applications connected' : 'No readable networks'} />} />
    </Section>
  </div>
}
