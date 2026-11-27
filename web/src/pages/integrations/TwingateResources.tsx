import { useEffect, useState, type ReactNode } from 'react'
import { Checkbox, CheckboxIndicator } from '@ui-sdk/react/checkbox'
import { Check, ChevronLeft, ChevronRight, Copy, RefreshCw } from 'lucide-react'
import { Button, Callout, DataTable, Status, type DataColumn } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'

type Protocol = { policy: string; ports: Array<{ start: number; end: number }> }

export type TwingateResource = {
  id: string
  name: string
  alias: string | null
  kind: string
  routing_mode?: string | null
  active: boolean
  address: { value: string }
  remote_network: { name: string }
  protocols: { tcp: Protocol; udp: Protocol; allow_icmp: boolean }
}

type ResourcePage = { resources: TwingateResource[]; total_count: number; next_cursor: string | null }

export function allowsSshPort({ protocols: { tcp } }: TwingateResource, port: number) {
  return Number.isInteger(port) && port >= 1 && port <= 65535 &&
    (tcp.policy === 'ALLOW_ALL' || (tcp.policy === 'RESTRICTED' && tcp.ports.some(({ start, end }) => port >= start && port <= end)))
}

function supportsSshGateway(resource: TwingateResource) {
  const address = resource.address.value.replace(/\/32$/, '')
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(address)) return false
  const octets = address.split('.').map(Number)
  const [first, second] = octets
  const privateAddress = octets.every((part) => part <= 255) &&
    (first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168))
  return resource.active && resource.kind === 'NetworkResource' && privateAddress &&
    (resource.routing_mode == null || resource.routing_mode === 'THROUGH_TWINGATE') &&
    (resource.protocols.tcp.policy === 'ALLOW_ALL' || resource.protocols.tcp.ports.some(({ start }) => allowsSshPort(resource, Math.max(1, start))))
}

function protocolLabel(name: string, protocol: Protocol) {
  if (protocol.policy === 'ALLOW_ALL') return `${name} all ports`
  if (!protocol.ports.length) return null
  const ranges = protocol.ports.map(({ start, end }) => start === end ? String(start) : `${start}–${end}`)
  return `${name} ${ranges.join(', ')}`
}

const resourceTypes: Record<string, string> = {
  NetworkResource: 'Network',
  SSHResource: 'SSH',
  KubernetesResource: 'Kubernetes',
  WebAppResource: 'Web app',
}

function resourceError(failure: unknown) {
  return failure instanceof Error ? failure.message : 'Twingate resources could not be loaded.'
}

export function TwingateResources({ onSetupGateway, renderAccess, onRefresh }: {
  renderAccess: (resource: TwingateResource) => ReactNode
  onSetupGateway?: (resource: TwingateResource) => void
  onRefresh: () => void
}) {
  const { request } = useControlPlane()
  const [page, setPage] = useState<(ResourcePage & { cursors: Array<string | null> })>()
  const [cursors, setCursors] = useState<Array<string | null>>([null])
  const [refresh, setRefresh] = useState(0)
  const [pending, setPending] = useState(true)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<Map<string, string>>(() => new Map())
  const [copyFeedback, setCopyFeedback] = useState('')
  const cursor = cursors.at(-1)

  useEffect(() => {
    const controller = new AbortController()
    const query = cursor ? `?after=${encodeURIComponent(cursor)}` : ''
    void request<ResourcePage>(`/v1/admin/integrations/twingate/resources${query}`, { signal: controller.signal })
      .then((result) => { if (!controller.signal.aborted) setPage({ ...result, cursors }) })
      .catch((failure: unknown) => { if (!controller.signal.aborted) setError(resourceError(failure)) })
      .finally(() => { if (!controller.signal.aborted) setPending(false) })
    return () => controller.abort()
  }, [cursor, cursors, refresh, request])

  function navigate(next: Array<string | null>) {
    setError('')
    setPending(true)
    setCursors(next)
    setRefresh((current) => current + 1)
  }

  function toggle(resource: TwingateResource, checked: boolean) {
    setCopyFeedback('')
    setSelected((current) => {
      const next = new Map(current)
      if (checked) next.set(resource.id, resource.name)
      else next.delete(resource.id)
      return next
    })
  }

  async function copySelection() {
    try {
      await navigator.clipboard.writeText([...selected.values()].join('\n'))
      setCopyFeedback('Resource names copied.')
    } catch {
      setCopyFeedback('Could not copy the selected resource names.')
    }
  }

  const columns: DataColumn<TwingateResource>[] = [
    {
      key: 'name',
      label: 'Resource',
      render: (row) => <>
        <label className="twingate-resource-name">
          <Checkbox className="twingate-checkbox" aria-label={`Select ${row.name}`} disabled={pending} checked={selected.has(row.id)} onCheckedChange={(checked) => toggle(row, checked === true)}>
            <CheckboxIndicator><Check size={13} aria-hidden="true" /></CheckboxIndicator>
          </Checkbox>
          <span><strong>{row.name}</strong><small>{resourceTypes[row.kind] ?? row.kind}</small></span>
        </label>
      </>,
    },
    {
      key: 'address',
      label: 'Address',
      render: (row) => <div className="twingate-address"><code>{row.address.value}</code>{row.alias && <small>Alias <span>{row.alias}</span></small>}</div>,
    },
    { key: 'network', label: 'Remote network', render: (row) => row.remote_network.name },
    {
      key: 'traffic',
      label: 'Allowed traffic',
      render: (row) => {
        const allowed = [
          protocolLabel('TCP', row.protocols.tcp),
          protocolLabel('UDP', row.protocols.udp),
          row.protocols.allow_icmp ? 'ICMP' : null,
        ].filter(Boolean)
        return allowed.length ? <div className="twingate-traffic">{allowed.map((label) => <span key={label}>{label}</span>)}</div> : 'None'
      },
    },
    { key: 'access', label: 'Laneway access', render: (row) => <div className="twingate-resource-access">
      {renderAccess(row)}
      {onSetupGateway && supportsSshGateway(row) && <Button variant="quiet" disabled={pending || Boolean(error)}
        aria-label={`Set up SSH access for ${row.name}`} onClick={() => onSetupGateway(row)}>Set up SSH access</Button>}
    </div> },
    { key: 'state', label: 'Status', render: (row) => <Status tone={row.active ? 'positive' : 'muted'}>{row.active ? 'Active' : 'Inactive'}</Status> },
  ]

  return <section className="twingate-inventory" aria-labelledby="twingate-inventory-title">
    <header className="twingate-inventory__header">
      <div className="twingate-inventory__title">
        <h2 id="twingate-inventory-title">Resources</h2>
        {page && <span className="twingate-count" aria-label={`${page.total_count} resources`}>{page.total_count}</span>}
      </div>
      <Button aria-label="Refresh resources" disabled={pending} onClick={() => {
        setSelected(new Map())
        setCopyFeedback('')
        navigate([null])
        onRefresh()
      }}><RefreshCw size={14} aria-hidden="true" />Refresh</Button>
    </header>
    {pending && <p className="twingate-inventory__message" role="status">{page ? 'Updating resources…' : 'Loading Twingate resources…'}</p>}
    {error && <div className="twingate-feedback" role="alert">
      <Callout tone="danger">{error}{page && <div>Showing the last loaded results from page {page.cursors.length}.</div>}</Callout>
      <Button onClick={() => navigate(cursors)}>Retry</Button>
    </div>}
    {page && <>
      <DataTable columns={columns} rows={page.resources} rowKey={(row) => row.id} rowClassName={(row) => selected.has(row.id) ? 'twingate-selected' : undefined} empty={<p>No resources in this Twingate network.</p>} />
      <footer className="twingate-inventory__footer">
        <div className="twingate-selection">
          <span aria-live="polite">{selected.size} selected</span>
          {selected.size > 0 && <Button variant="quiet" onClick={() => void copySelection()} aria-label={`Copy ${selected.size} selected`}><Copy size={14} aria-hidden="true" />Copy names</Button>}
          {copyFeedback && <span role="status">{copyFeedback}</span>}
        </div>
        <div className="twingate-pagination">
          <span>Page {page.cursors.length}</span>
          {page.cursors.length > 1 && <Button aria-label="Previous page" disabled={pending} onClick={() => navigate(page.cursors.slice(0, -1))}><ChevronLeft size={16} aria-hidden="true" /></Button>}
          {!error && page.next_cursor && <Button aria-label="Next page" disabled={pending} onClick={() => navigate([...page.cursors, page.next_cursor])}><ChevronRight size={16} aria-hidden="true" /></Button>}
        </div>
      </footer>
    </>}
  </section>
}
