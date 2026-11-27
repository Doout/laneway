import { useEffect, useState } from 'react'
import { Button, Callout, DataTable, Section, Status, type DataColumn } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'

type Protocol = { policy: string; ports: Array<{ start: number; end: number }> }

type Resource = {
  id: string
  name: string
  alias: string | null
  kind: string
  active: boolean
  address: { value: string }
  remote_network: { name: string }
  protocols: { tcp: Protocol; udp: Protocol; allow_icmp: boolean }
}

type ResourcePage = { resources: Resource[]; total_count: number; next_cursor: string | null }

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

export function TwingateResources() {
  const { request } = useControlPlane()
  const [page, setPage] = useState<ResourcePage>()
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
      .then((result) => { if (!controller.signal.aborted) setPage(result) })
      .catch((failure: unknown) => { if (!controller.signal.aborted) setError(resourceError(failure)) })
      .finally(() => { if (!controller.signal.aborted) setPending(false) })
    return () => controller.abort()
  }, [cursor, refresh, request])

  function navigate(next: Array<string | null>) {
    setError('')
    setPending(true)
    setCursors(next)
    setRefresh((current) => current + 1)
  }

  function toggle(resource: Resource) {
    setCopyFeedback('')
    setSelected((current) => {
      const next = new Map(current)
      if (next.has(resource.id)) next.delete(resource.id)
      else next.set(resource.id, resource.name)
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

  const columns: DataColumn<Resource>[] = [
    {
      key: 'name',
      label: 'Resource',
      render: (row) => <>
        <label className="twingate-resource-name">
          <input type="checkbox" aria-label={`Select ${row.name}`} checked={selected.has(row.id)} onChange={() => toggle(row)} />
          <strong>{row.name}</strong>
        </label>
        <small>{resourceTypes[row.kind] ?? row.kind}</small>
      </>,
    },
    {
      key: 'address',
      label: 'Address',
      render: (row) => <><code>{row.address.value}</code>{row.alias ? <small>{row.alias}</small> : null}</>,
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
        return allowed.length ? allowed.join(' · ') : '—'
      },
    },
    { key: 'state', label: 'Twingate status', render: (row) => <Status tone={row.active ? 'positive' : 'muted'}>{row.active ? 'Active' : 'Inactive'}</Status> },
  ]

  return <Section
    title="Twingate resources"
    meta={page ? `${page.total_count} ${page.total_count === 1 ? 'resource' : 'resources'}` : undefined}
    action={<Button disabled={pending} onClick={() => {
      setSelected(new Map())
      setCopyFeedback('')
      navigate([null])
    }}>Refresh resources</Button>}
  >
    {pending ? <p role="status">Loading Twingate resources…</p> : error ? (
      <div role="alert"><Callout tone="danger">{error}</Callout></div>
    ) : page ? (
      <DataTable columns={columns} rows={page.resources} rowKey={(row) => row.id} empty={<p>No resources in this Twingate network.</p>} />
    ) : null}
    <div className="button-row twingate-resource-controls">
      {cursors.length > 1 ? <Button disabled={pending} onClick={() => navigate(cursors.slice(0, -1))}>Previous page</Button> : null}
      {!error && page?.next_cursor ? <Button disabled={pending} onClick={() => navigate([...cursors, page.next_cursor])}>Next page</Button> : null}
      {selected.size ? <Button variant="quiet" onClick={() => void copySelection()}>Copy {selected.size} selected</Button> : null}
      {copyFeedback ? <span role="status">{copyFeedback}</span> : null}
    </div>
  </Section>
}
