import { useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowRight, Ban, FileKey2, Network, RadioTower, ShieldCheck } from 'lucide-react'
import { Button, Field, FormStack, PageHeader, RecordList, ResourceLink, SearchField, Section, Status } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'
import { DashboardEmpty, ErrorMessage, Missing, SummaryStrip, VisibilityToolbar, certificateState, time, type RecordVisibility } from './shared'

export function InfrastructurePage() {
  const { inventory, hasPermission } = useControlPlane()
  const network = inventory?.network
  const records = inventory?.relays ?? []
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const visibleRecords = visibility === 'all' ? records : records.filter((relay) => relay.enabled)
  return <><PageHeader title="Infrastructure" action={network && hasPermission('relay.manage', network.network_id) ? <Button to="/infrastructure/relays/new" variant="primary"><RadioTower size={16} />Register relay</Button> : undefined} /><SummaryStrip label="Infrastructure summary" items={[{ label: 'Networks', value: inventory?.networks.length ?? 0 }, { label: 'IPv4 space', value: network?.ipv4_pool ?? 'Not set', detail: network?.name ?? 'No network' }, { label: 'Relays online', value: records.filter((relay) => relay.enabled).length, detail: `${records.length} registered`, tone: records.some((relay) => relay.enabled) ? 'positive' : undefined }, { label: 'Coverage', value: records.some((relay) => relay.enabled) ? 'Available' : 'Direct only' }]} /><div className="infrastructure-spotlight"><div><h2>{network?.name ?? 'No active network'}</h2><p>{network ? `${network.ipv4_pool}${network.ipv6_pool ? ` · ${network.ipv6_pool}` : ''}` : 'No network'}</p></div><Button to="/networks" variant="secondary">Networks <ArrowRight size={14} /></Button></div><VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Enabled relays only" visible={visibleRecords.length} total={records.length} /><div className="infrastructure-grid"><Section title="Network" meta="Current">{network ? <ResourceLink to={`/infrastructure/networks/${network.network_id}`} icon={<Network size={19} />} title={network.name} meta={`Epoch ${network.configuration_epoch} · ${network.ipv4_pool}`} state={<Status tone="positive">Active</Status>} /> : <div className="inline-empty">No network.</div>}</Section><Section title="Relays" meta={records.length ? `${records.length} registered` : undefined}>{visibleRecords.length ? <div className="resource-list">{visibleRecords.map((relay) => <ResourceLink key={relay.relay_id} to={`/infrastructure/relays/${relay.relay_id}`} icon={<RadioTower size={19} />} title={relay.name} meta={relay.endpoint} state={<Status tone={relay.enabled ? 'positive' : 'muted'}>{relay.enabled ? 'Enabled' : 'Disabled'}</Status>} />)}</div> : <DashboardEmpty icon={<RadioTower size={18} />} title="No enabled relays" />}</Section></div></>
}

export function NetworkPage() {
  const { networkId } = useParams()
  const { inventory, hasPermission, selectNetwork } = useControlPlane()
  const network = inventory?.networks.find((candidate) => candidate.network_id === networkId)
  if (!network) return <Missing title="Network not found" back="/infrastructure" />
  if (inventory?.network?.network_id !== network.network_id) {
    return <PageHeader title={network.name} action={<Button variant="primary" onClick={() => selectNetwork(network.network_id)}>Select network</Button>} />
  }
  return <><PageHeader title={network.name} action={<div className="button-row">{hasPermission('route.manage', network.network_id) ? <Button to="/routes/new">Add route</Button> : null}{hasPermission('enrollment.issue', network.network_id) ? <Button to="/nodes/new" variant="primary">Add node</Button> : null}</div>} /><RecordList rows={[["Network ID", <code>{network.network_id}</code>], ["IPv4 pool", <code>{network.ipv4_pool}</code>], ["IPv6 pool", <code>{network.ipv6_pool ?? 'Not configured'}</code>], ["Configuration epoch", network.configuration_epoch]]} /></>
}

export function RelayPage() {
  const { relayId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [serviceId, setServiceId] = useState('')
  const [error, setError] = useState('')
  if (!relayId) {
    async function register(event: FormEvent<HTMLFormElement>) {
      event.preventDefault(); if (!inventory?.network) return
      try { const created = await request<{ relay_id: string }>(`/v1/admin/networks/${inventory.network.network_id}/relays`, { method: 'POST', body: { service_id: serviceId.trim(), name: name.trim(), endpoint: endpoint.trim() } }); await refresh(); navigate(`/infrastructure/relays/${created.relay_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Relay registration failed.') }
    }
    return <><PageHeader title="Register relay" /><FormStack onSubmit={register}><Field label="Relay name"><input placeholder="relay-east" value={name} onChange={(event) => setName(event.target.value)} /></Field><Field label="Advertised endpoint"><input placeholder="relay.example.com:443" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} /></Field><Field label="Relay service ID"><input value={serviceId} onChange={(event) => setServiceId(event.target.value)} /></Field><ErrorMessage value={error} /><Button type="submit" variant="primary">Register relay</Button></FormStack></>
  }
  const relay = inventory?.relays.find((candidate) => candidate.relay_id === relayId)
  if (!relay) return <Missing title="Relay not found" back="/infrastructure" />
  const activeRelay = relay
  const canManage = hasPermission('relay.manage', relay.network_id)
  async function toggle() { try { if (activeRelay.enabled) await request(`/v1/admin/relays/${activeRelay.relay_id}/disable`, { method: 'POST' }); else await request(`/v1/admin/relays/${activeRelay.relay_id}`, { method: 'PUT', body: { name: activeRelay.name, endpoint: activeRelay.endpoint, enabled: true } }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Relay update failed.') } }
  return <><PageHeader title={relay.name} action={<Button to="/infrastructure">Infrastructure</Button>} /><RecordList rows={[["Relay ID", <code>{relay.relay_id}</code>], ["Service ID", <code>{relay.service_id}</code>], ["Endpoint", <code>{relay.endpoint}</code>], ["State", relay.enabled ? 'Enabled' : 'Disabled']]} /><ErrorMessage value={error} />{canManage ? <Button variant={relay.enabled ? 'danger' : 'primary'} onClick={() => void toggle()}>{relay.enabled ? 'Disable relay' : 'Enable relay'}</Button> : null}</>
}

export function SecurityPage() {
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const [error, setError] = useState('')
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const [query, setQuery] = useState('')
  const records = inventory?.certificates ?? []
  const normalizedQuery = query.trim().toLowerCase()
  const visibleRecords = records.filter((certificate) => (visibility === 'all' || certificateState(certificate).label === 'Valid') && (!normalizedQuery || [certificate.serial, certificate.certificate_id, certificate.node_id].some((value) => value.toLowerCase().includes(normalizedQuery))))
  const validRecords = records.filter((certificate) => certificateState(certificate).label === 'Valid')
  const expiringSoon = validRecords.filter((certificate) => certificate.not_after_unix_seconds <= Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60)
  async function revoke(networkId: string, serial: string) { const reason = window.prompt('Revocation reason'); if (!reason) return; try { await request(`/v1/admin/networks/${networkId}/certificates/${serial}/revoke`, { method: 'POST', body: { reason } }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Certificate revocation failed.') } }
  return <><PageHeader title="Security" /><ErrorMessage value={error} /><div className="security-posture"><span className="security-posture__icon"><ShieldCheck aria-hidden="true" size={22} /></span><div><h2>{records.length && validRecords.length === records.length ? 'All certificates are valid' : records.length ? 'Review inactive certificates' : 'No certificates issued'}</h2></div><Status tone={records.length && validRecords.length !== records.length ? 'warning' : 'positive'}>{records.length && validRecords.length !== records.length ? 'Review' : 'Healthy'}</Status></div><SummaryStrip label="Certificate summary" items={[{ label: 'Valid', value: validRecords.length, detail: `${records.length} issued`, tone: 'positive' }, { label: 'Expiring soon', value: expiringSoon.length, detail: 'within 30 days', tone: expiringSoon.length ? 'warning' : undefined }, { label: 'Revoked', value: records.filter((certificate) => certificateState(certificate).label === 'Revoked').length }, { label: 'Expired', value: records.filter((certificate) => certificateState(certificate).label === 'Expired').length }]} /><VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Valid only" visible={visibleRecords.length} total={records.length}><SearchField label="Search certificates" placeholder="Search serial, certificate, or Node ID" value={query} onChange={setQuery} /></VisibilityToolbar><section className="certificate-grid" aria-label="Certificate inventory">{visibleRecords.length ? visibleRecords.map((certificate) => { const state = certificateState(certificate); return <article key={certificate.certificate_id} className="certificate-card"><header><span className="certificate-card__icon"><FileKey2 aria-hidden="true" size={20} /></span><div><span>Certificate serial</span><h2>{certificate.serial}</h2></div><Status tone={state.tone}>{state.label}</Status></header><RecordList rows={[["Certificate ID", <code>{certificate.certificate_id}</code>], ["Node ID", <code>{certificate.node_id}</code>], ["Valid from", time(certificate.not_before_unix_seconds)], ["Valid until", time(certificate.not_after_unix_seconds)]]} />{state.label !== 'Revoked' && hasPermission('certificate.revoke', certificate.network_id) ? <footer><Button variant="danger" onClick={() => void revoke(certificate.network_id, certificate.serial)}><Ban size={16} />Revoke certificate</Button></footer> : null}</article> }) : <div className="data-empty"><p>No certificates match this view.</p></div>}</section></>
}
