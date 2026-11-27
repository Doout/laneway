import { useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ChevronRight, Network, Plug, RadioTower } from 'lucide-react'
import { Button, Field, FormStack, PageHeader, RecordList, ResourceLink, SearchField, Status } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'
import { ErrorMessage, Missing, VisibilityToolbar, certificateState, time, type RecordVisibility } from './shared'
import './operations.css'

export function InfrastructurePage() {
  const { inventory, hasPermission } = useControlPlane()
  const network = inventory?.network
  const canReadRelays = Boolean(network && hasPermission('relay.read', network.network_id))
  const canRegisterRelay = Boolean(network && hasPermission('relay.manage', network.network_id))
  const records = inventory?.relays ?? []
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const enabled = records.filter((relay) => relay.enabled)
  const visibleRecords = visibility === 'all' ? records : enabled

  return (
    <div className="operations-page">
      <PageHeader title="Infrastructure" action={canRegisterRelay ? <Button to="/infrastructure/relays/new" variant="primary"><RadioTower aria-hidden="true" size={16} />Register relay</Button> : undefined} />
      <div className="operations-workspace">
        <section className="operations-group" aria-labelledby="relay-inventory-title">
          <header className="operations-group-heading"><h2 id="relay-inventory-title">Relays</h2></header>
          <div className="operations-inventory-facts" role="group" aria-label="Infrastructure summary">
            {canReadRelays ? <>
              <span><strong>{enabled.length}</strong> <span>Enabled relays</span></span>
              <span><span>Runtime status</span> <strong>Not reported</strong></span>
              <span>No relay health telemetry</span>
            </> : <span>Not authorized</span>}
          </div>
          {canReadRelays ? <>
            <VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Enabled relays only" visible={visibleRecords.length} total={records.length} />
            {visibleRecords.length ? <div className="operations-link-list">{visibleRecords.map((relay) => (
              <ResourceLink key={relay.relay_id} to={`/infrastructure/relays/${relay.relay_id}`} icon={<RadioTower size={16} />} title={relay.name} meta={relay.endpoint} state={<Status tone={relay.enabled ? 'positive' : 'muted'}>{relay.enabled ? 'Enabled' : 'Disabled'}</Status>} />
            ))}</div> : <p className="operations-empty">{visibility === 'current' ? 'No enabled relays' : 'No relays registered'}</p>}
          </> : <div className="operations-empty"><strong>Relay inventory unavailable</strong><p>This administrator cannot read relay records.</p></div>}
        </section>
        <aside className="operations-side" aria-label="Network scope and integrations">
          <section className="operations-group" aria-labelledby="operations-network-title">
            <header className="operations-group-heading"><h2 id="operations-network-title">Current network</h2><Button to="/networks" variant="quiet">Networks</Button></header>
            {network ? <>
              <div className="operations-link-list"><ResourceLink to={`/infrastructure/networks/${network.network_id}`} icon={<Network size={16} />} title={network.name} meta={`Epoch ${network.configuration_epoch}`} state={<Status tone="muted">Configured</Status>} /></div>
              <RecordList rows={[['IPv4 pool', <code>{network.ipv4_pool}</code>], ['IPv6 pool', network.ipv6_pool ? <code>{network.ipv6_pool}</code> : 'Not configured']]} />
            </> : <p className="operations-empty">No selected network</p>}
          </section>
          {hasPermission('integration.manage') ? <section className="operations-group" aria-labelledby="operations-integrations-title">
            <header className="operations-group-heading"><h2 id="operations-integrations-title">Network integrations</h2></header>
            <div className="operations-link-list"><ResourceLink to="/infrastructure/integrations/twingate" icon={<Plug size={16} />} title="Twingate" meta="Resource access and bridge health" /></div>
          </section> : null}
        </aside>
      </div>
    </div>
  )
}

export function NetworkPage() {
  const { networkId } = useParams()
  const { inventory, hasPermission, selectNetwork } = useControlPlane()
  const network = inventory?.networks.find((candidate) => candidate.network_id === networkId)
  if (!network) return <Missing title="Network not found" back="/infrastructure" />

  const selected = inventory?.network?.network_id === network.network_id
  const canAddRoute = selected && hasPermission('route.manage', network.network_id)
  const canAddNode = selected && hasPermission('enrollment.issue', network.network_id)

  return (
    <div className="operations-page operations-detail">
      <PageHeader title={network.name} action={!selected ? <Button variant="primary" onClick={() => selectNetwork(network.network_id)}>Select network</Button> : (canAddRoute || canAddNode) ? (
        <div className="button-row">{canAddRoute ? <Button to="/routes/new">Add route</Button> : null}{canAddNode ? <Button to="/nodes/new" variant="primary">Add node</Button> : null}</div>
      ) : undefined} />
      {selected ? <div className="operations-workspace">
        <section className="operations-group" aria-labelledby="network-address-title">
          <header className="operations-group-heading"><h2 id="network-address-title">Address pools</h2></header>
          <RecordList rows={[['IPv4 pool', <code>{network.ipv4_pool}</code>], ['IPv6 pool', network.ipv6_pool ? <code>{network.ipv6_pool}</code> : 'Not configured']]} />
        </section>
        <section className="operations-group" aria-labelledby="network-record-title">
          <header className="operations-group-heading"><h2 id="network-record-title">Network record</h2><Status tone="muted">Selected network</Status></header>
          <RecordList rows={[['Network ID', <code>{network.network_id}</code>], ['Configuration epoch', network.configuration_epoch]]} />
        </section>
      </div> : null}
    </div>
  )
}

export function RelayPage() {
  const { relayId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [serviceId, setServiceId] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const network = inventory?.network

  if (!relayId) {
    async function register(event: FormEvent<HTMLFormElement>) {
      event.preventDefault()
      if (!network || pending) return
      setError('')
      setPending(true)
      try {
        const created = await request<{ relay_id: string }>(`/v1/admin/networks/${network.network_id}/relays`, { method: 'POST', body: { service_id: serviceId.trim(), name: name.trim(), endpoint: endpoint.trim() } })
        await refresh()
        navigate(`/infrastructure/relays/${created.relay_id}`)
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : 'Relay registration failed.')
      } finally {
        setPending(false)
      }
    }
    return (
      <div className="operations-page operations-registration">
        <PageHeader title="Register relay" />
        <div className="operations-workspace">
          <section className="operations-group" aria-labelledby="relay-identity-title">
            <header className="operations-group-heading"><h2 id="relay-identity-title">Relay identity</h2></header>
            <FormStack onSubmit={register}>
              <Field label="Relay name"><input required value={name} onChange={(event) => setName(event.target.value)} /></Field>
              <Field label="Advertised endpoint" hint="Reachable hostname or IP address and port."><input placeholder="relay.example.com:443" required value={endpoint} onChange={(event) => setEndpoint(event.target.value)} /></Field>
              <Field label="Relay service ID" hint="Use the service ID from the provisioned relay certificate."><input autoCapitalize="none" spellCheck={false} required value={serviceId} onChange={(event) => setServiceId(event.target.value)} /></Field>
              <ErrorMessage value={error} />
              <div className="button-row"><Button type="submit" variant="primary" disabled={pending || !network}>{pending ? 'Registering…' : 'Register relay'}</Button><Button to="/infrastructure" variant="quiet">Cancel</Button></div>
            </FormStack>
          </section>
          <section className="operations-group" aria-labelledby="relay-scope-title">
            <header className="operations-group-heading"><h2 id="relay-scope-title">Network scope</h2></header>
            {network ? <RecordList rows={[['Network', network.name], ['IPv4 pool', <code>{network.ipv4_pool}</code>]]} /> : <p className="operations-empty">No selected network</p>}
          </section>
        </div>
      </div>
    )
  }

  const relay = inventory?.relays.find((candidate) => candidate.relay_id === relayId)
  if (!relay) return <Missing title="Relay not found" back="/infrastructure" />
  const activeRelay = relay
  const canManage = hasPermission('relay.manage', relay.network_id)

  async function toggle() {
    if (pending) return
    setError('')
    setPending(true)
    try {
      if (activeRelay.enabled) await request(`/v1/admin/relays/${activeRelay.relay_id}/disable`, { method: 'POST' })
      else await request(`/v1/admin/relays/${activeRelay.relay_id}`, { method: 'PUT', body: { name: activeRelay.name, endpoint: activeRelay.endpoint, enabled: true } })
      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Relay update failed.')
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="operations-page operations-detail">
      <PageHeader title={relay.name} />
      <div className="operations-workspace">
        <section className="operations-group" aria-labelledby="relay-connection-title">
          <header className="operations-group-heading"><h2 id="relay-connection-title">Connection</h2></header>
          <RecordList rows={[['Endpoint', <code>{relay.endpoint}</code>], ['Relay ID', <code>{relay.relay_id}</code>], ['Service ID', <code>{relay.service_id}</code>]]} />
        </section>
        <section className="operations-group" aria-labelledby="relay-availability-title">
          <header className="operations-group-heading"><h2 id="relay-availability-title">Availability</h2><Status tone={relay.enabled ? 'positive' : 'muted'}>{relay.enabled ? 'Enabled' : 'Disabled'}</Status></header>
          <RecordList rows={[['Network', network?.network_id === relay.network_id ? network.name : <code>{relay.network_id}</code>]]} />
          <ErrorMessage value={error} />
          {canManage ? <div className="operations-record-actions"><Button variant={relay.enabled ? 'danger' : 'primary'} onClick={() => void toggle()} disabled={pending}>{relay.enabled ? 'Disable relay' : 'Enable relay'}</Button></div> : null}
        </section>
      </div>
    </div>
  )
}

export function SecurityPage() {
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const [error, setError] = useState('')
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const [query, setQuery] = useState('')
  const now = Math.floor(Date.now() / 1000)
  const expiresBy = now + 30 * 24 * 60 * 60
  const records = (inventory?.certificates ?? []).map((certificate) => ({ certificate, state: certificateState(certificate, now) }))
  const normalizedQuery = query.trim().toLowerCase()
  const visibleRecords = records.filter(({ certificate, state }) => (visibility === 'all' || state.label === 'Valid') && (!normalizedQuery || [certificate.serial, certificate.certificate_id, certificate.node_id].some((value) => value.toLowerCase().includes(normalizedQuery))))
  const validRecords = records.filter(({ state }) => state.label === 'Valid')
  const expiringSoon = validRecords.filter(({ certificate }) => certificate.not_after_unix_seconds <= expiresBy)

  async function revoke(networkId: string, serial: string) {
    const reason = window.prompt('Revocation reason')
    if (!reason) return
    try {
      await request(`/v1/admin/networks/${networkId}/certificates/${serial}/revoke`, { method: 'POST', body: { reason } })
      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Certificate revocation failed.')
    }
  }

  return (
    <div className="operations-page operations-security">
      <PageHeader title="Security" />
      <ErrorMessage value={error} />
      <section className="operations-group" aria-labelledby="certificate-inventory-title">
        <header className="operations-group-heading"><h2 id="certificate-inventory-title">Certificates</h2></header>
        <div className="operations-inventory-facts" role="group" aria-label="Certificate summary">
          <span><strong>{validRecords.length}</strong> valid</span>
          <span className={expiringSoon.length ? 'operations-warning' : undefined}><strong>{expiringSoon.length}</strong> expiring within 30 days</span>
          <span><strong>{records.filter(({ state }) => state.label === 'Revoked').length}</strong> revoked</span>
          <span><strong>{records.filter(({ state }) => state.label === 'Expired').length}</strong> expired</span>
        </div>
        <VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Valid only" visible={visibleRecords.length} total={records.length}>
          <SearchField label="Search certificates" placeholder="Search serial, certificate, or node ID" value={query} onChange={setQuery} />
        </VisibilityToolbar>
        <div className="operations-certificate-list">
          {visibleRecords.length ? visibleRecords.map(({ certificate, state }) => {
            const expiring = state.label === 'Valid' && certificate.not_after_unix_seconds <= expiresBy
            return <details key={certificate.certificate_id}>
              <summary>
                <ChevronRight aria-hidden="true" size={15} />
                <span className="operations-certificate-identity"><code>{certificate.serial}</code><small>Node <code>{certificate.node_id}</code></small></span>
                <span className="operations-certificate-expiry"><small>Valid until</small> {time(certificate.not_after_unix_seconds)}</span>
                <Status tone={expiring ? 'warning' : state.tone}>{expiring ? 'Expiring soon' : state.label}</Status>
              </summary>
              <div className="operations-certificate-detail">
                <RecordList rows={[['Certificate ID', <code>{certificate.certificate_id}</code>], ['Valid from', time(certificate.not_before_unix_seconds)]]} />
                {state.label !== 'Revoked' && hasPermission('certificate.revoke', certificate.network_id) ? <div className="operations-record-actions"><Button variant="danger" onClick={() => void revoke(certificate.network_id, certificate.serial)}>Revoke certificate</Button></div> : null}
              </div>
            </details>
          }) : <p className="operations-empty">{records.length ? 'No certificates match this view.' : 'No certificates issued.'}</p>}
        </div>
      </section>
    </div>
  )
}
