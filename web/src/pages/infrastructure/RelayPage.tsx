import { useEffect, useState, type FormEvent } from 'react'
import { AlertTriangle, ArrowRight, Check, Network, RadioTower, RotateCw, ServerCog } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { Button, Callout, ConfirmPanel, EmptyState, Field, FormStack, PageHeader, Status } from '../../components/ui'
import {
  INFRASTRUCTURE_ACTOR,
  registerInfrastructureRelay,
  rotateInfrastructureRelayCertificate,
  setInfrastructureRelayEnabled,
  type InfrastructureRelay,
} from '../../lib/infrastructure-state'
import { useInfrastructureView } from './useInfrastructureView'
import './infrastructure.css'

type RelayAction = 'enable' | 'disable' | 'rotate'

function parseIpv4Address(value: string) {
  const octets = value.split('.')
  if (octets.length !== 4 || octets.some((octet) => !/^(0|[1-9]\d{0,2})$/.test(octet) || Number(octet) > 255)) return null
  return octets.map(Number)
}

function parseIpv6Address(value: string) {
  if (!value || value.includes('%')) return null
  const halves = value.split('::')
  if (halves.length > 2) return null
  const left = halves[0] ? halves[0].split(':') : []
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const tokens = [...left, ...right]
  const dottedIndexes = tokens.flatMap((token, index) => token.includes('.') ? [index] : [])
  if (dottedIndexes.length > 1 || (dottedIndexes.length === 1 && (dottedIndexes[0] !== tokens.length - 1 || (halves.length === 2 && left.includes(tokens[dottedIndexes[0]]))))) return null

  const groups: number[] = []
  for (const token of tokens) {
    if (token.includes('.')) {
      const ipv4 = parseIpv4Address(token)
      if (!ipv4) return null
      groups.push((ipv4[0] << 8) | ipv4[1], (ipv4[2] << 8) | ipv4[3])
    } else {
      if (!/^[0-9a-f]{1,4}$/i.test(token)) return null
      groups.push(Number.parseInt(token, 16))
    }
  }
  if (halves.length === 1 ? groups.length !== 8 : groups.length >= 8) return null

  const leftGroupCount = left.reduce((count, token) => count + (token.includes('.') ? 2 : 1), 0)
  const expanded = halves.length === 1
    ? groups
    : [...groups.slice(0, leftGroupCount), ...Array(8 - groups.length).fill(0), ...groups.slice(leftGroupCount)]
  return expanded.flatMap((group) => [group >> 8, group & 0xff])
}

function isUsableIpv4(address: number[]) {
  return !address.every((octet) => octet === 0)
    && !(address[0] >= 224 && address[0] <= 239)
    && !address.every((octet) => octet === 255)
}

function isUsableIpv6(address: number[]) {
  return !address.every((octet) => octet === 0)
    && address[0] !== 0xff
    && !(address.slice(0, 10).every((octet) => octet === 0) && address[10] === 0xff && address[11] === 0xff)
}

function isValidDnsHost(value: string) {
  const host = value.endsWith('.') ? value.slice(0, -1) : value
  if (!host || host.length > 253) return false
  return host.split('.').every((label) => label.length >= 1
    && label.length <= 63
    && /^[a-z0-9-]+$/i.test(label)
    && !label.startsWith('-')
    && !label.endsWith('-'))
}

function isValidRelayEndpoint(value: string) {
  let host = ''
  let portText = ''
  let bracketed = false
  if (value.startsWith('[')) {
    const match = value.match(/^\[([^\]]+)\]:([0-9]+)$/)
    if (!match) return false
    ;[, host, portText] = match
    bracketed = true
  } else {
    const match = value.match(/^([^:]+):([0-9]+)$/)
    if (!match) return false
    ;[, host, portText] = match
  }
  const port = Number(portText)
  if (!Number.isInteger(port) || port < 1 || port > 65_535) return false
  if (bracketed) {
    const address = parseIpv6Address(host)
    return Boolean(address && isUsableIpv6(address))
  }
  const address = parseIpv4Address(host)
  return address ? isUsableIpv4(address) : isValidDnsHost(host)
}

function isValidRelayServiceId(value: string) {
  return /^[0-9a-f]{32}$/.test(value) && !/^0{32}$/.test(value)
}

function TypedRelayAction({ relay, action, live, onCancel, onConfirm }: { relay: InfrastructureRelay; action: RelayAction; live?: boolean; onCancel: () => void; onConfirm: () => void | Promise<void> }) {
  const [confirmation, setConfirmation] = useState('')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const copy: Record<RelayAction, { title: string; impact: string; button: string; variant: 'primary' | 'danger' }> = {
    enable: { title: `Enable ${relay.name}?`, impact: live ? `Enables ${relay.endpoint} for its assigned network.` : `After a successful probe, ${relay.endpoint} can carry encrypted fallback traffic. Direct connections and route ownership are unchanged.`, button: 'Enable relay', variant: 'primary' },
    disable: { title: `Disable ${relay.name}?`, impact: live ? 'Disables this relay. Direct connections and route ownership are unchanged.' : `Stops new fallback sessions and health probes. ${relay.sessions} active session${relay.sessions === 1 ? '' : 's'} will end; direct connections are unchanged.`, button: 'Disable relay', variant: 'danger' },
    rotate: { title: `Rotate ${relay.name} certificate?`, impact: `Replaces the certificate immediately. The relay must reload it; ${relay.sessions} active fallback session${relay.sessions === 1 ? '' : 's'} may reconnect.`, button: 'Rotate certificate', variant: 'danger' },
  }
  const selected = copy[action]
  async function execute() {
    setPending(true)
    setError('')
    try { await onConfirm() } catch (caught) { setError(caught instanceof Error ? caught.message : 'The relay could not be updated. Try again.'); setPending(false) }
  }
  return (
    <ConfirmPanel icon={action === 'rotate' ? <RotateCw size={28} /> : <AlertTriangle size={28} />} title={selected.title} description={selected.impact}>
      <div className="infra-confirm-field"><Field label={`Type “${relay.name}” to confirm`}><input autoComplete="off" onChange={(event) => setConfirmation(event.target.value)} value={confirmation} /></Field></div>
      {error ? <p className="infra-form-error" role="alert">{error}</p> : null}
      <div className="button-row"><Button disabled={pending || confirmation !== relay.name} onClick={execute} variant={selected.variant}>{pending ? 'Applying…' : selected.button}</Button><Button disabled={pending} onClick={onCancel} variant="secondary">Cancel</Button></div>
    </ConfirmPanel>
  )
}

function RelayRegistrationPage() {
  const { networks, relays, live, inventory, request, refresh } = useInfrastructureView()
  const registrationNetworks = live ? networks.filter((network) => network.id === inventory?.network?.network_id) : networks
  const [name, setName] = useState(live ? '' : 'sin-relay-01')
  const [endpoint, setEndpoint] = useState(live ? '' : 'relay.sin.example.test:443')
  const [networkId, setNetworkId] = useState(registrationNetworks[0]?.id ?? 'all')
  const [serviceId, setServiceId] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [submitted, setSubmitted] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [confirmation, setConfirmation] = useState('')
  const [registeredRelay, setRegisteredRelay] = useState<{ id: string; name: string; enabled: boolean; actor?: string } | null>(null)
  const [actionPending, setActionPending] = useState(false)
  const [actionError, setActionError] = useState('')

  useEffect(() => {
    if (live && networkId === 'all' && registrationNetworks[0]) setNetworkId(registrationNetworks[0].id)
  }, [live, networkId, registrationNetworks])

  const nameError = submitted && name.trim().length < 3 ? 'Enter a relay name with at least 3 characters.' : submitted && relays.some((relay) => relay.name.toLowerCase() === name.trim().toLowerCase()) ? 'A relay with this name already exists.' : undefined
  const endpointError = submitted && !isValidRelayEndpoint(endpoint.trim()) ? 'Use a hostname or IP followed by a port from 1 to 65535.' : submitted && relays.some((relay) => relay.endpoint.toLowerCase() === endpoint.trim().toLowerCase()) ? 'This relay endpoint is already registered.' : undefined
  const serviceIdError = submitted && live && !isValidRelayServiceId(serviceId.trim()) ? 'Use a nonzero 32-character lowercase hexadecimal service ID.' : undefined
  const selectedNetwork = networkId === 'all' ? 'All networks' : networks.find((network) => network.id === networkId)?.name ?? 'Unknown network'
  const impact = live
    ? `Registers ${name.trim()} at ${endpoint.trim()} for ${selectedNetwork} as ${enabled ? 'enabled' : 'disabled'}.`
    : enabled
      ? `${name.trim()} receives a controller-issued certificate and becomes eligible to carry encrypted fallback traffic for ${selectedNetwork} after its first successful health probe. It starts with 0 sessions and cannot decrypt payloads.`
      : `${name.trim()} receives a controller-issued certificate and is stored for ${selectedNetwork}, but health probes and fallback selection remain disabled.`

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitted(true)
    const validName = name.trim().length >= 3 && !relays.some((relay) => relay.name.toLowerCase() === name.trim().toLowerCase())
    const validEndpoint = isValidRelayEndpoint(endpoint.trim()) && !relays.some((relay) => relay.endpoint.toLowerCase() === endpoint.trim().toLowerCase())
    if (validName && validEndpoint && (!live || isValidRelayServiceId(serviceId.trim())) && (!live || networkId !== 'all')) { setConfirmation(''); setConfirming(true) }
  }

  async function handleRegister() {
    if (confirmation !== name.trim()) return
    setActionPending(true)
    setActionError('')
    try {
      if (live) {
        const relay = await request<{ relay_id: string }>(`/v1/admin/networks/${networkId}/relays`, { method: 'POST', body: { service_id: serviceId.trim(), name: name.trim(), endpoint: endpoint.trim() } })
        await refresh()
        setRegisteredRelay({ id: relay.relay_id, name: name.trim(), enabled: true })
      } else {
        const relay = registerInfrastructureRelay({ name, endpoint, networkId, enabled })
        setRegisteredRelay({ id: relay.id, name: relay.name, enabled: relay.enabled, actor: relay.updatedBy })
      }
      setSubmitted(false)
      setConfirming(false)
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'The relay could not be registered. Try again.')
    } finally {
      setActionPending(false)
    }
  }

  return (
    <>
      <PageHeader title="Register relay" action={<Button to="/infrastructure" variant="secondary">Back to infrastructure</Button>} />
      {registeredRelay ? <div className="infra-success" role="status"><Check aria-hidden="true" size={17} /><span><strong>{registeredRelay.name} registered{live ? '.' : ` by ${registeredRelay.actor}.`}</strong> {registeredRelay.enabled ? live ? 'Enabled.' : 'Enabled and awaiting its first health probe.' : 'Saved disabled with no traffic eligibility.'}</span><Link to={`/infrastructure/relays/${registeredRelay.id}`}>Open relay <ArrowRight aria-hidden="true" size={15} /></Link></div> : null}

      <div className="infra-relay-form-grid">
        <section className="infra-panel infra-relay-form" aria-labelledby="relay-form-title">
          <div className="infra-panel-head"><div><h2 id="relay-form-title">{confirming ? 'Confirm registration' : 'Relay identity'}</h2></div><RadioTower aria-hidden="true" size={19} /></div>
          {confirming ? (
            <div className="infra-registration-confirm">
              <Callout tone={enabled ? 'warning' : 'neutral'}>{impact}</Callout>
              <Field label={`Type “${name.trim()}” to confirm`}><input autoComplete="off" onChange={(event) => setConfirmation(event.target.value)} value={confirmation} /></Field>
              {actionError ? <p className="infra-form-error" role="alert">{actionError}</p> : null}
              <div className="button-row"><Button disabled={actionPending || confirmation !== name.trim()} onClick={handleRegister} variant="primary">{actionPending ? 'Registering…' : live ? 'Register relay' : 'Generate credential'}</Button><Button disabled={actionPending} onClick={() => { setConfirming(false); setConfirmation(''); setActionError('') }} variant="quiet">Cancel</Button></div>
            </div>
          ) : (
            <FormStack onSubmit={handleSubmit}>
              <div className="infra-field-pair"><Field label="Relay name" error={nameError}><input aria-invalid={Boolean(nameError)} maxLength={100} onChange={(event) => setName(event.target.value)} value={name} /></Field><Field label="Advertised endpoint" error={endpointError}><input aria-invalid={Boolean(endpointError)} onChange={(event) => setEndpoint(event.target.value)} value={endpoint} /></Field></div>
              <Field label="Network scope"><select disabled={!registrationNetworks.length} onChange={(event) => setNetworkId(event.target.value)} value={networkId}>{registrationNetworks.map((network) => <option key={network.id} value={network.id}>{network.name}</option>)}{!live ? <option value="all">All networks</option> : null}</select></Field>
              {live ? <Field label="Relay service ID" hint="Existing service ID for this relay." error={serviceIdError}><input aria-invalid={Boolean(serviceIdError)} autoCapitalize="none" maxLength={32} onChange={(event) => setServiceId(event.target.value)} spellCheck={false} value={serviceId} /></Field> : null}
              {!live ? <label className="infra-check"><input checked={enabled} onChange={(event) => setEnabled(event.target.checked)} type="checkbox" /> Enable after the first successful health probe</label> : null}
              <div className="button-row"><Button type="submit" variant="primary">Review registration</Button><Button to="/infrastructure" variant="quiet">Cancel</Button></div>
            </FormStack>
          )}
        </section>
        <aside className="infra-panel infra-impact-preview" aria-labelledby="relay-impact-title">
          <div className="infra-panel-head"><div><h2 id="relay-impact-title">Registration</h2></div><Status tone={enabled ? live ? 'positive' : 'warning' : 'muted'}>{enabled ? live ? 'Enabled' : 'Awaiting probe' : 'Disabled'}</Status></div>
          {!live ? <div className="infra-mini-path"><span><ServerCog aria-hidden="true" size={16} /> Enrolled nodes</span><ArrowRight aria-hidden="true" size={14} /><span><RadioTower aria-hidden="true" size={16} /> {name.trim() || 'Relay'}</span><ArrowRight aria-hidden="true" size={14} /><span><Network aria-hidden="true" size={16} /> {selectedNetwork}</span></div> : null}
          <dl className="infra-record-list"><div><dt>Endpoint</dt><dd><code>{endpoint.trim() || 'Not set'}</code></dd></div>{live ? <><div><dt>Service ID</dt><dd><code>{serviceId.trim() || 'Not set'}</code></dd></div><div><dt>State</dt><dd>{enabled ? 'Enabled' : 'Disabled'}</dd></div></> : <><div><dt>Initial sessions</dt><dd>0</dd></div><div><dt>Payload access</dt><dd>None · encrypted</dd></div><div><dt>Credential</dt><dd>Single-use after review</dd></div><div><dt>Attributed to</dt><dd>{INFRASTRUCTURE_ACTOR}</dd></div></>}</dl>
        </aside>
      </div>
    </>
  )
}

function RelayDetailPage({ relay }: { relay: InfrastructureRelay }) {
  const { networks, relays, live, request, refresh } = useInfrastructureView()
  const [action, setAction] = useState<RelayAction | null>(null)
  const networkName = relay.networkId === 'all' ? 'All networks' : networks.find((network) => network.id === relay.networkId)?.name ?? 'Deleted network'
  const stateLabel = !relay.enabled ? 'Disabled' : live ? 'Enabled' : relay.reachable ? 'Reachable' : 'Awaiting probe'
  const stateTone = !relay.enabled ? 'muted' : live || relay.reachable ? 'positive' : 'warning'

  async function applyAction() {
    if (!action) return
    if (live) {
      if (action === 'rotate') throw new Error('Certificate rotation is not supported by the current controller API.')
      if (action === 'disable') await request(`/v1/admin/relays/${relay.id}/disable`, { method: 'POST' })
      if (action === 'enable') await request(`/v1/admin/relays/${relay.id}`, { method: 'PUT', body: { name: relay.name, endpoint: relay.endpoint, enabled: true } })
      await refresh()
    } else if (action === 'rotate') rotateInfrastructureRelayCertificate(relay.id)
    else setInfrastructureRelayEnabled(relay.id, action === 'enable')
    setAction(null)
  }

  if (action) return <TypedRelayAction action={action} live={live} onCancel={() => setAction(null)} onConfirm={applyAction} relay={relay} />

  return (
    <>
      <PageHeader title="Relays" action={<Button to="/infrastructure/relays/new" variant="primary">Register relay</Button>} />
      <div className="infra-relay-master-detail">
        <section className="infra-panel infra-relay-master" aria-label="Relay inventory">
          <div className="infra-panel-head"><div><h2>Relay inventory</h2><p>{relays.length} relays</p></div></div>
          {relays.map((record) => <Link className={record.id === relay.id ? 'is-selected' : undefined} key={record.id} to={`/infrastructure/relays/${record.id}`}><span className="infra-record-icon"><RadioTower aria-hidden="true" size={16} /></span><span><strong>{record.name}</strong><small>{record.endpoint}</small></span><Status tone={!record.enabled ? 'muted' : live || record.reachable ? 'positive' : 'warning'}>{!record.enabled ? 'Disabled' : live ? 'Enabled' : record.reachable ? 'Enabled' : 'Awaiting probe'}</Status>{live ? null : <small>{record.sessions} sessions</small>}</Link>)}
        </section>
        <section className="infra-panel infra-relay-detail" aria-labelledby="relay-detail-title">
          <div className="infra-panel-head"><div><div className="infra-detail-title"><span className="infra-record-icon"><RadioTower aria-hidden="true" size={19} /></span><span><h2 id="relay-detail-title">{relay.name}</h2><code>{relay.id}</code></span></div></div><Status tone={stateTone}>{stateLabel}</Status></div>
          {!live ? <div className="infra-relay-path"><span><ServerCog aria-hidden="true" size={16} /> Direct path</span><span className="infra-relay-path-line">fallback only</span><span><RadioTower aria-hidden="true" size={16} /> {relay.name}</span><span className="infra-relay-path-line">encrypted</span><span><Network aria-hidden="true" size={16} /> {networkName}</span></div> : null}
          <dl className="infra-record-list"><div><dt>Endpoint</dt><dd><code>{relay.endpoint}</code></dd></div><div><dt>Network scope</dt><dd>{networkName}</dd></div>{live ? <><div><dt>Created</dt><dd>{relay.createdAt ?? '—'}</dd></div><div><dt>Configuration epoch</dt><dd>{relay.configurationEpoch ?? '—'}</dd></div></> : <><div><dt>Active sessions</dt><dd>{relay.sessions} fallback</dd></div><div><dt>Last probe</dt><dd>{relay.lastProbe}</dd></div><div><dt>Certificate</dt><dd>{relay.certificateDays} days remaining</dd></div><div><dt>Latest result</dt><dd>{relay.lastAction}</dd></div><div><dt>Actor</dt><dd>{relay.updatedBy}</dd></div><div><dt>Recorded</dt><dd>{relay.updatedAt}</dd></div></>}</dl>
          <div className="button-row"><Button onClick={() => setAction(relay.enabled ? 'disable' : 'enable')} variant={relay.enabled ? 'quiet' : 'primary'}>{relay.enabled ? 'Disable relay' : 'Enable relay'}</Button><Button disabled={live} onClick={() => setAction('rotate')} title={live ? 'Certificate rotation is not supported by the current controller API.' : undefined} variant="secondary"><RotateCw aria-hidden="true" size={16} /> {live ? 'Rotation unavailable in live mode' : 'Rotate certificate'}</Button></div>
        </section>
      </div>
    </>
  )
}

export function RelayPage() {
  const { relayId } = useParams()
  const { relays } = useInfrastructureView()
  if (!relayId) return <RelayRegistrationPage />
  const relay = relays.find((record) => record.id === relayId)
  if (!relay) return <EmptyState icon={<RadioTower size={32} />} title="Relay not found" description={`No relay matches “${relayId}”.`} action={<Button to="/infrastructure" variant="primary">Return to infrastructure</Button>} />
  return <RelayDetailPage relay={relay} />
}
