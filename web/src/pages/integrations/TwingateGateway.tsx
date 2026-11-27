import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Button, Callout, Field, FormStack, Status } from '../../components/ui'
import { type ControllerNetwork, type ControllerNode, useControlPlane } from '../../lib/control-plane'
import { allowsSshPort, TwingateResources, type TwingateResource } from './TwingateResources'

const endpoint = '/v1/admin/integrations/twingate/gateway'
const pollIntervalMs = 5_000

type GatewayConfig = {
  network_id: string
  client_node_id: string
  resource_id: string
  tcp_port: number
}

type GatewayClientEdit = { gatewayId: string; previousClientId: string }
type GatewayAction =
  | { kind: 'enable'; body: GatewayConfig }
  | ({ kind: 'update'; body: GatewayConfig } & GatewayClientEdit)
  | { kind: 'disable'; gatewayId: string }

type GatewayState = 'disabled' | 'provisioning' | 'ready' | 'degraded' | 'removing'
type GatewayStatus = {
  state: GatewayState
  gateway_id: string | null
  network_id: string | null
  client_node_id: string | null
  resource_id: string | null
  destination: string | null
  tcp_port: number | null
  runtime_available: boolean
  detail: string | null
}

const statusLabels = {
  disabled: 'Disabled',
  provisioning: 'Provisioning',
  ready: 'Online',
  degraded: 'Needs attention',
  removing: 'Removing',
}
const statusTones = {
  disabled: 'muted',
  provisioning: 'warning',
  ready: 'positive',
  degraded: 'danger',
  removing: 'warning',
} as const

function errorMessage(failure: unknown, fallback: string) {
  return failure instanceof Error ? failure.message : fallback
}

function savedConfig(status: GatewayStatus | undefined): GatewayConfig | undefined {
  if (!status?.network_id || !status.client_node_id || !status.resource_id || status.tcp_port === null) return
  return {
    network_id: status.network_id,
    client_node_id: status.client_node_id,
    resource_id: status.resource_id,
    tcp_port: status.tcp_port,
  }
}

function useGatewayClients(networkId: string, attempt: number) {
  const { request } = useControlPlane()
  const [lookup, setLookup] = useState<{ networkId: string; attempt: number; nodes?: ControllerNode[]; error?: string }>()

  useEffect(() => {
    if (!networkId) return
    const controller = new AbortController()
    const path = `/v1/admin/networks/${encodeURIComponent(networkId)}/nodes?limit=1000`
    void request<{ nodes: ControllerNode[] }>(path, { signal: controller.signal })
      .then((result) => {
        if (controller.signal.aborted) return
        const now = Date.now() / 1000
        const nodes = result.nodes.filter((node) => node.network_id === networkId && node.ipv4_address &&
          node.revoked_at_unix_seconds == null && (node.lease_expires_at_unix_seconds == null || node.lease_expires_at_unix_seconds > now))
        setLookup({ networkId, attempt, nodes })
      })
      .catch((failure: unknown) => {
        if (!controller.signal.aborted) setLookup({ networkId, attempt, error: errorMessage(failure, 'Laneway clients could not be loaded.') })
      })
    return () => controller.abort()
  }, [attempt, networkId, request])

  return lookup?.networkId === networkId && lookup.attempt === attempt ? lookup : undefined
}

function GatewayClientField({ clients, clientId, disabled, loading, onChange }: {
  clients: ControllerNode[] | undefined
  clientId: string
  disabled: boolean
  loading: boolean
  onChange: (client: string) => void
}) {
  return <Field label="Permitted client" hint={clients?.length === 0 ? 'Enroll a client with an IPv4 address in this network to continue.' : undefined}>
    <select disabled={disabled || !clients?.length} required value={clientId} onChange={(event) => onChange(event.target.value)}>
      <option value="" disabled>{loading ? 'Loading clients…' : 'Choose a client'}</option>
      {clients?.map((node) => <option key={node.node_id} value={node.node_id}>{node.name} ({node.ipv4_address})</option>)}
    </select>
  </Field>
}

function GatewayForm({ resource, disabled, onCancel, onEnable }: {
  resource: TwingateResource
  disabled: boolean
  onCancel: () => void
  onEnable: (config: GatewayConfig) => void
}) {
  const { request } = useControlPlane()
  const [networks, setNetworks] = useState<ControllerNetwork[]>()
  const [networkChoice, setNetworkChoice] = useState('')
  const [clientChoice, setClientChoice] = useState('')
  const [port, setPort] = useState(allowsSshPort(resource, 22) ? '22' : '')
  const [networkError, setNetworkError] = useState('')
  const [attempt, setAttempt] = useState(0)

  const networkId = networkChoice || (networks?.length === 1 ? networks[0].network_id : '')
  const clients = useGatewayClients(networkId, attempt)
  const availableClients = clients?.nodes
  const error = networkError || clients?.error
  const clientId = clientChoice || (availableClients?.length === 1 ? availableClients[0].node_id : '')
  const portValid = allowsSshPort(resource, Number(port))
  const canEnable = availableClients?.some((node) => node.node_id === clientId) && portValid
  const { tcp } = resource.protocols

  useEffect(() => {
    const controller = new AbortController()
    void request<{ networks: ControllerNetwork[] }>('/v1/admin/networks?limit=100', { signal: controller.signal })
      .then((result) => { if (!controller.signal.aborted) setNetworks(result.networks) })
      .catch((failure: unknown) => {
        if (!controller.signal.aborted) setNetworkError(errorMessage(failure, 'Laneway networks could not be loaded.'))
      })
    return () => controller.abort()
  }, [attempt, request])

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!canEnable || error || disabled) return
    onEnable({ network_id: networkId, client_node_id: clientId, resource_id: resource.id, tcp_port: Number(port) })
  }

  return <FormStack onSubmit={submit}>
    <p className="twingate-gateway__description">Allow one Laneway client to reach <strong>{resource.name}</strong> at <code>{resource.address.value}</code>. The saved Twingate token needs <strong>Read, Write &amp; Provision</strong> permissions.</p>
    <Field label="Laneway network" hint={networks?.length === 0 ? 'Create a Laneway network to continue.' : undefined}>
      <select disabled={disabled || !networks?.length} required value={networkId} onChange={(event) => {
        setClientChoice('')
        setNetworkChoice(event.target.value)
      }}>
        <option value="" disabled>{networks ? 'Choose a network' : 'Loading networks…'}</option>
        {networks?.map((network) => <option key={network.network_id} value={network.network_id}>{network.name}</option>)}
      </select>
    </Field>
    <GatewayClientField clients={availableClients} clientId={clientId} disabled={disabled}
      loading={Boolean(networkId) && !clients} onChange={setClientChoice} />
    <Field label="SSH port" hint={tcp.policy === 'RESTRICTED' ? `Allowed TCP ports ${tcp.ports.map(({ start, end }) => start === end ? String(start) : `${start}–${end}`).join(', ')}.` : undefined}
      error={port && !portValid ? 'Enter a TCP port allowed by this Twingate resource.' : undefined}>
      <input disabled={disabled} type="number" min={1} max={65535} step={1} required value={port} onChange={(event) => setPort(event.target.value)} />
    </Field>
    {error && <div role="alert"><Callout tone="danger">{error}</Callout></div>}
    <div className="button-row">
      {error && <Button disabled={disabled} onClick={() => { setNetworkError(''); setAttempt((current) => current + 1) }}>Reload networks and clients</Button>}
      <Button type="submit" variant="primary" disabled={disabled || !canEnable || Boolean(error)}>Enable gateway</Button>
      <Button disabled={disabled} variant="quiet" onClick={onCancel}>Cancel</Button>
    </div>
  </FormStack>
}

function GatewayClientForm({ config, disabled, onCancel, onSave }: {
  config: GatewayConfig
  disabled: boolean
  onCancel: () => void
  onSave: (config: GatewayConfig) => void
}) {
  const [attempt, setAttempt] = useState(0)
  const [clientId, setClientId] = useState(config.client_node_id)
  const lookup = useGatewayClients(config.network_id, attempt)
  const canSave = !disabled && clientId !== config.client_node_id && lookup?.nodes?.some((node) => node.node_id === clientId)

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (canSave) onSave({ ...config, client_node_id: clientId })
  }

  return <FormStack onSubmit={submit}>
    <p className="twingate-gateway__description">Switch SSH access to another client in this Laneway network.</p>
    <GatewayClientField clients={lookup?.nodes} clientId={clientId} disabled={disabled}
      loading={!lookup} onChange={setClientId} />
    {lookup?.error && <div role="alert"><Callout tone="danger">{lookup.error}</Callout></div>}
    <div className="button-row">
      {lookup?.error && <Button disabled={disabled} onClick={() => setAttempt((current) => current + 1)}>Reload clients</Button>}
      <Button type="submit" variant="primary" disabled={!canSave}>Save permitted client</Button>
      <Button disabled={disabled} variant="quiet" onClick={onCancel}>Cancel</Button>
    </div>
  </FormStack>
}

export function TwingateGateway() {
  const { inventory, request } = useControlPlane()
  const [status, setStatus] = useState<GatewayStatus>()
  const [resource, setResource] = useState<TwingateResource>()
  const [statusError, setStatusError] = useState('')
  const [writeError, setWriteError] = useState('')
  const [action, setAction] = useState<GatewayAction['kind']>()
  const [refresh, setRefresh] = useState(0)
  const [disableGatewayId, setDisableGatewayId] = useState<string>()
  const [clientEdit, setClientEdit] = useState<GatewayClientEdit>()
  const readController = useRef<AbortController>(null)
  const heading = useRef<HTMLHeadingElement>(null)
  const active = status !== undefined && status.state !== 'disabled'
  const config = savedConfig(status)
  const gatewayNetworkId = status?.network_id ?? ''
  const gatewayClients = useGatewayClients(inventory?.network?.network_id !== gatewayNetworkId ? gatewayNetworkId : '', refresh)

  useEffect(() => {
    if (action) return
    const controller = new AbortController()
    readController.current = controller
    let timer: ReturnType<typeof setTimeout> | undefined

    async function poll(watch: boolean) {
      if (watch && document.hidden) {
        timer = setTimeout(() => void poll(true), pollIntervalMs)
        return
      }
      try {
        const result = await request<GatewayStatus>(endpoint, { signal: controller.signal })
        if (controller.signal.aborted) return
        setStatus(result)
        setStatusError('')
        watch = result.state !== 'disabled'
        if (watch) setResource(undefined)
      } catch (failure) {
        if (controller.signal.aborted) return
        setStatusError(errorMessage(failure, 'Gateway status could not be loaded.'))
      }
      if (watch) timer = setTimeout(() => void poll(true), pollIntervalMs)
    }

    void poll(active)
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [action, active, refresh, request])

  useEffect(() => {
    if (resource || clientEdit) heading.current?.focus()
  }, [clientEdit, resource])

  async function apply(next: GatewayAction) {
    const method = next.kind === 'disable' ? 'DELETE' : 'PUT'
    const body = next.kind === 'disable' ? undefined : next.body
    const match = next.kind === 'disable' ? next.gatewayId : next.kind === 'update' ? `${next.gatewayId}:${next.previousClientId}` : undefined
    const ifMatch = match ? JSON.stringify(match) : undefined
    readController.current?.abort()
    setAction(next.kind)
    setWriteError('')
    setDisableGatewayId(undefined)
    try {
      const result = await request<GatewayStatus>(endpoint, { method, body, ifMatch })
      setStatus(result)
      setStatusError('')
      setResource(undefined)
      setClientEdit(undefined)
      heading.current?.focus()
    } catch (failure) {
      const fallback = { enable: 'Gateway setup failed.', update: 'Permitted client could not be changed.', disable: 'Gateway removal failed.' }
      setWriteError(errorMessage(failure, fallback[next.kind]))
    } finally {
      setAction(undefined)
    }
  }

  const controlsDisabled = Boolean(action || statusError)
  const canSetUp = status?.state === 'disabled' && status.runtime_available && !controlsDisabled
  const state = status?.state
  const gatewayId = status?.gateway_id
  const busyLabel = action ? { enable: 'Enabling…', update: 'Updating access…', disable: 'Removing…' }[action] : null
  const networkName = inventory?.networks.find((network) => network.network_id === status?.network_id)?.name
  const client = inventory?.nodes.find((node) => node.node_id === status?.client_node_id) ??
    gatewayClients?.nodes?.find((node) => node.node_id === status?.client_node_id)
  const destination = status?.destination && status.tcp_port !== null ? `${status.destination}:${status.tcp_port}` : null
  const detail = status?.detail ?? (active && !status.runtime_available ? 'The managed gateway worker is unavailable.' : null)
  const editing = clientEdit && state === 'ready' && clientEdit.gatewayId === gatewayId && clientEdit.previousClientId === config?.client_node_id

  const gatewayPanel = <section key="gateway" className="twingate-gateway" aria-labelledby="twingate-gateway-title">
    <header className="twingate-gateway__header">
      <h2 id="twingate-gateway-title" ref={heading} tabIndex={-1}>Managed SSH gateway</h2>
      <div role="status">
        {busyLabel ? <Status tone="warning">{busyLabel}</Status> :
          statusError ? <Status tone="danger">Status unavailable</Status> :
          state ? <Status tone={statusTones[state]}>{statusLabels[state]}</Status> :
          <Status tone="muted">Checking…</Status>}
      </div>
    </header>
    {active && <div className="twingate-gateway__details">
      {destination && <dl className="twingate-gateway__metadata">
        <div><dt>SSH destination</dt><dd><code>{destination}</code></dd></div>
        <div><dt>Laneway network</dt><dd>{networkName ?? status.network_id}</dd></div>
        <div><dt>Permitted client</dt><dd>{client?.name ?? status.client_node_id}</dd></div>
      </dl>}
      {detail && <Callout tone={state === 'degraded' ? 'warning' : 'neutral'}>{detail}</Callout>}
      {gatewayId && gatewayId === disableGatewayId && state !== 'removing' ? <div>
        <p className="twingate-gateway__description">Disable access to this destination and remove the managed gateway?</p>
        <div className="button-row">
          <Button variant="danger" disabled={controlsDisabled} onClick={() => void apply({ kind: 'disable', gatewayId })}>Confirm disable</Button>
          <Button variant="quiet" onClick={() => setDisableGatewayId(undefined)}>Cancel</Button>
        </div>
      </div> : !editing && <div className="button-row">
        {state === 'ready' && config && gatewayId && <Button disabled={controlsDisabled} onClick={() => {
          setWriteError('')
          setClientEdit({ gatewayId, previousClientId: config.client_node_id })
        }}>Change permitted client</Button>}
        {state === 'degraded' && config && status.runtime_available && <Button disabled={controlsDisabled} onClick={() => void apply({ kind: 'enable', body: config })}>Retry setup</Button>}
        {gatewayId && (state === 'removing' ? <Button disabled={controlsDisabled} onClick={() => void apply({ kind: 'disable', gatewayId })}>Retry removal</Button> :
          <Button disabled={controlsDisabled} onClick={() => setDisableGatewayId(gatewayId)}>Disable gateway</Button>)}
      </div>}
    </div>}
    {editing && config && clientEdit && <GatewayClientForm
      key={clientEdit.gatewayId}
      config={config}
      disabled={controlsDisabled}
      onCancel={() => { setClientEdit(undefined); setWriteError(''); heading.current?.focus() }}
      onSave={(body) => void apply({ kind: 'update', body, ...clientEdit })}
    />}
    {status?.state === 'disabled' && !resource && !action && !statusError && <p className="twingate-gateway__description twingate-gateway__hint">
      {status.runtime_available ? 'Set up a gateway from an active private IPv4 network resource that allows TCP.' : 'Managed gateways are unavailable on this controller.'}
    </p>}
    {state === 'disabled' && resource && <GatewayForm
      key={resource.id}
      resource={resource}
      disabled={!canSetUp}
      onCancel={() => { setResource(undefined); setWriteError('') }}
      onEnable={(body) => void apply({ kind: 'enable', body })}
    />}
    {statusError && <div className="twingate-feedback" role="alert">
      <Callout tone="danger">{statusError}</Callout>
      <Button onClick={() => setRefresh((current) => current + 1)}>Check gateway status</Button>
    </div>}
    {writeError && <div className="twingate-feedback" role="alert"><Callout tone="danger">{writeError}</Callout></div>}
  </section>

  const inventoryPanel = <TwingateResources
    key="inventory"
    onRefresh={() => setRefresh((current) => current + 1)}
    onSetupGateway={canSetUp ? (next) => { setWriteError(''); setResource(next) } : undefined}
  />
  return active || resource || action ? [gatewayPanel, inventoryPanel] : [inventoryPanel, gatewayPanel]
}
