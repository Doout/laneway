import { FormEvent, useEffect, useMemo, useState } from 'react'
import { ArrowRight, Check, Clipboard, KeyRound, Laptop, MonitorDot, Network, PlugZap, RotateCcw, Server, ShieldCheck, Trash2, TriangleAlert } from 'lucide-react'
import { useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  Button,
  Callout,
  ChoiceGroup,
  ConfirmPanel,
  DataTable,
  DetailLayout,
  EmptyState,
  EntityTitle,
  Field,
  FilterSelect,
  FormLayout,
  FormStack,
  IdentityBlock,
  PageHeader,
  ReviewPanel,
  SearchField,
  Section,
  Status,
  TokenBox,
  Toolbar,
} from '../../components/ui'
import { type NodeRecord } from '../../lib/demo-data'
import { controllerOrigin, useControlPlane } from '../../lib/control-plane'
import { controllerNodes } from '../../lib/live-records'
import { attributed, persistedNodes, readDemoState, updateDemoState, type NodeCapabilities } from '../../lib/persisted-demo-state'
import './nodes.css'

const nodeToken = 'lnw_node_01J8ATLAS_8eK3yF4pM2sQ9vR6'
const defaultCapabilities: NodeCapabilities = { publish: true, accept: true, exit: false, relay: true }
type IssuedNodeToken = { id?: string; name?: string; nodeClass?: string; expiry?: string; token?: string }
let liveIssuedNodeToken: IssuedNodeToken | null = null

function controllerCapabilities(mask: number): NodeCapabilities {
  return { publish: (mask & 8) !== 0, accept: false, exit: (mask & 16) !== 0, relay: false }
}

function nodeForId(records: NodeRecord[], id?: string) {
  return records.find(node => node.id === id || node.name === id)
}

function NodeNotFound({ id }: { id?: string }) {
  return <EmptyState icon={<TriangleAlert />} title="Node not found" description={`No node matches ${id ? `“${id}”` : 'this address'}.`} action={<Button to="/nodes" variant="primary">Return to nodes</Button>} />
}

function nodeIcon(kind: NodeRecord['enrollmentClass']) {
  if (kind === 'Connector') return <PlugZap size={17} />
  if (kind === 'Exit node') return <Network size={17} />
  if (kind.includes('user')) return <Laptop size={17} />
  return <Server size={17} />
}

export function NodesListPage() {
  const { live, inventory, inventoryError, inventoryPending } = useControlPlane()
  const records = live ? controllerNodes(inventory?.nodes ?? []) : persistedNodes()
  const [query, setQuery] = useState('')
  const [enrollment, setEnrollment] = useState('all')
  const [state, setState] = useState('all')
  const [selectedId, setSelectedId] = useState<string | undefined>(records[0]?.id)

  const filteredNodes = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return records.filter(node => {
      const matchesQuery = !needle || [node.name, node.id, node.addresses].some(value => value.toLowerCase().includes(needle))
      const matchesEnrollment = enrollment === 'all' || node.enrollmentClass === enrollment
      const matchesState = state === 'all' || node.state === state
      return matchesQuery && matchesEnrollment && matchesState
    })
  }, [enrollment, query, records, state])
  const selected = records.find(node => node.id === selectedId) ?? filteredNodes[0]

  return <>
    <PageHeader
      title={`${records.length} Nodes`}
      description={live ? inventory?.network?.name : 'Home network'}
      action={<Button to="/nodes/new" variant="primary"><MonitorDot size={17} />Add node</Button>}
    />
    {inventoryError ? <Callout tone="danger">{inventoryError}</Callout> : null}
    <div className="nodes-segments" role="group" aria-label="Quick node filters">
      {(live ? ['all', 'Enrolled', 'Lease expired', 'Revoked'] : ['all', 'Connected', 'Relay fallback', 'Enrollment pending', 'Revoked']).map(option => <button type="button" key={option} className={state === option ? 'is-active' : undefined} onClick={() => setState(option)}>{option === 'all' ? 'All nodes' : option}</button>)}
    </div>
    <Toolbar filters={<>
      <FilterSelect label="Filter by enrollment class" value={enrollment} onChange={setEnrollment}>
        <option value="all">All enrollment classes</option>
        {!live ? <option value="Connector">Connectors</option> : null}
        <option value="Durable">Durable nodes</option>
        {!live ? <option value="Exit node">Exit nodes</option> : null}
        <option value="Remembered user">Remembered users</option>
        <option value="Ephemeral user">Ephemeral users</option>
      </FilterSelect>
      <FilterSelect label="Filter by state" value={state} onChange={setState}>
        <option value="all">All states</option>
        {live ? <><option value="Enrolled">Enrolled</option><option value="Lease expired">Lease expired</option></> : <><option value="Connected">Connected</option><option value="Relay fallback">Relay fallback</option><option value="Offline">Offline</option><option value="Enrollment pending">Enrollment pending</option></>}
        <option value="Revoked">Revoked</option>
      </FilterSelect>
      <span className="nodes-result-count" aria-live="polite">{filteredNodes.length} shown</span>
    </>}>
      <SearchField label="Search nodes" placeholder="Search name, address, or node ID" value={query} onChange={setQuery} />
    </Toolbar>
    <div className="nodes-workspace">
      <div className="nodes-table-panel" aria-busy={inventoryPending}>
        <DataTable
          rows={filteredNodes}
          rowKey={node => node.id}
          rowClassName={node => node.id === selected?.id ? 'is-selected' : undefined}
          empty={<EmptyState icon={<MonitorDot />} title="No nodes match" description="Clear a filter or try a different name, address, or node ID." action={<Button onClick={() => { setQuery(''); setEnrollment('all'); setState('all') }}><RotateCcw size={16} />Reset filters</Button>} />}
          columns={[
            { key: 'node', label: 'Node', render: node => <button type="button" className="nodes-row-select" onClick={() => setSelectedId(node.id)}><EntityTitle icon={nodeIcon(node.enrollmentClass)} subtitle={node.id}>{node.name}</EntityTitle></button> },
            { key: 'class', label: 'Enrollment', render: node => node.enrollmentClass },
            ...(live ? [{ key: 'roles', label: 'Policy roles', render: (node: NodeRecord) => node.capabilityRoles?.join(', ') || 'None' }] : []),
            { key: 'addresses', label: 'Overlay addresses', render: node => <code className="nodes-address">{node.addresses}</code> },
            { key: 'seen', label: live ? 'Created' : 'Last seen', render: node => live ? (() => { const timestamp = inventory?.nodes.find(record => record.node_id === node.id)?.created_at_unix_seconds; return timestamp ? new Date(timestamp * 1000).toLocaleDateString() : '—' })() : node.lastSeen },
            { key: 'state', label: 'State', render: node => <Status tone={node.tone}>{node.state}</Status> },
            { key: 'actions', label: 'Actions', align: 'end', render: node => <Button to={node.name === 'atlas-gateway' ? '/nodes/atlas-gateway' : `/nodes/${node.id}`} variant="quiet">View</Button> },
          ]}
        />
      </div>
      {selected ? <aside className="node-inspector">
        <div className="node-inspector__heading"><span className="node-inspector__icon">{nodeIcon(selected.enrollmentClass)}</span><div><small>Selected node</small><h2>{selected.name}</h2></div><Status tone={selected.tone}>{selected.state}</Status></div>
        <dl className="node-inspector__facts"><div><dt>Overlay</dt><dd><code>{selected.addresses}</code></dd></div><div><dt>Enrollment</dt><dd>{selected.enrollmentClass}</dd></div>{live ? <div><dt>Policy roles</dt><dd>{selected.capabilityRoles?.join(', ') || 'None'}</dd></div> : null}<div><dt>Node ID</dt><dd><code>{selected.id}</code></dd></div></dl>
        {!live ? <div className="node-inspector__path"><small>Effective path</small><div><span>{selected.name}</span><i /><span>Direct QUIC</span><i /><span>Private route</span></div><p>{selected.state === 'Relay fallback' ? 'Direct negotiation failed; using relay.' : 'Direct QUIC.'}</p></div> : null}
        <Button to={selected.name === 'atlas-gateway' ? '/nodes/atlas-gateway' : `/nodes/${selected.id}`} variant="primary">Open node <ArrowRight size={16} /></Button>
      </aside> : null}
    </div>
  </>
}

export function AddNodePage() {
  const navigate = useNavigate()
  const { live, inventory, inventoryPending, request } = useControlPlane()
  const [name, setName] = useState('')
  const [nodeClass, setNodeClass] = useState('Durable')
  const [networkName, setNetworkName] = useState('Production')
  const [expiry, setExpiry] = useState('24 hours')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const selectedNetworkName = live ? inventory?.network?.name ?? 'Loading controller network…' : networkName

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const cleanName = name.trim()
    if (cleanName.length < 3) {
      setError('Enter a node name with at least 3 characters.')
      return
    }
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(cleanName)) {
      setError('Use letters, numbers, periods, underscores, or hyphens; begin with a letter or number.')
      return
    }
    setError('')
    if (live) {
      const networkId = inventory?.network?.network_id
      if (!networkId) {
        setError('No controller network is available for enrollment.')
        return
      }
      const expirySeconds = expiry === '1 hour' ? 3600 : expiry === '7 days' ? 604800 : 86400
      const enabledCapabilities = nodeClass === 'Connector' ? 8 : nodeClass === 'Exit node' ? 16 : 0
      setPending(true)
      try {
        const issued = await request<{ enrollment_token: string; token_id: string; expires_at_unix_seconds: number }>('/v1/admin/enrollment-tokens', {
          method: 'POST',
          body: {
            network_id: networkId,
            label: `${cleanName} enrollment`,
            expires_at_unix_seconds: Math.floor(Date.now() / 1000) + expirySeconds,
            enrollment_class: 'durable',
            requested_name: cleanName,
            enabled_capabilities: enabledCapabilities,
          },
        })
        liveIssuedNodeToken = { name: cleanName, nodeClass, expiry, token: issued.enrollment_token }
        navigate('/nodes/new/token')
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : 'Unable to issue the enrollment token.')
      } finally {
        setPending(false)
      }
      return
    }
    const id = `nod_demo_${cleanName.toLowerCase().replace(/[^a-z0-9]+/g, '_')}`
    const record: NodeRecord = { id, name: cleanName, enrollmentClass: nodeClass as NodeRecord['enrollmentClass'], addresses: 'Assigned on enrollment', lastSeen: 'Never', state: 'Enrollment pending', tone: 'warning' }
    updateDemoState(current => ({ ...current, nodes: { ...current.nodes, [id]: { ...attributed('Enrollment token issued'), record, capabilities: defaultCapabilities } } }))
    navigate('/nodes/new/token', { state: { id, name: cleanName, nodeClass, networkName, expiry } })
  }

  return <>
    <PageHeader title="Add node" description="Create a single-use enrollment token." />
    <FormLayout
      form={<FormStack onSubmit={submit}>
        <Field label="Node name" hint="Shown in route and audit records." error={error}>
          <input value={name} onChange={event => { setName(event.target.value); if (error) setError('') }} placeholder="e.g. warehouse-connector-01" autoComplete="off" aria-invalid={Boolean(error)} />
        </Field>
        <ChoiceGroup label="Enrollment class" value={nodeClass} onChange={setNodeClass} options={[
          { value: 'Durable', label: 'Durable node', description: 'Long-lived machine or administrator device.' },
          { value: 'Connector', label: 'Connector', description: 'Use the operator-managed encrypted Docker bootstrap; console onboarding is unavailable.', disabled: true },
          { value: 'Exit node', label: 'Exit node', description: 'Requires a separately configured privileged runtime; console onboarding is unavailable.', disabled: true },
        ]} />
        <Field label="Network">
          <select value={selectedNetworkName} disabled={live} onChange={event => setNetworkName(event.target.value)}>{live ? <option>{selectedNetworkName}</option> : <><option>Production</option><option>Home lab</option><option>Staging</option></>}</select>
        </Field>
        <Field label="Token expires" hint="The issued token is shown once on the next screen.">
          <select value={expiry} onChange={event => setExpiry(event.target.value)}><option>1 hour</option><option>24 hours</option><option>7 days</option></select>
        </Field>
        <div className="button-row"><Button type="submit" variant="primary" disabled={pending || (live && !inventory?.network)}><KeyRound size={17} />{pending ? 'Issuing token…' : live && (inventoryPending || !inventory?.network) ? 'Loading network…' : 'Issue enrollment token'}</Button><Button to="/nodes" variant="quiet">Cancel</Button></div>
      </FormStack>}
      review={<ReviewPanel title="Enrollment review" rows={[
        ['Name', name.trim() || 'Not set'],
        ['Class', nodeClass],
        ['Network', selectedNetworkName],
        ['Expires', expiry],
        ['Redemptions', 'One'],
      ]} />}
    />
  </>
}

export function NodeTokenPage() {
  const location = useLocation()
  const { live, inventory } = useControlPlane()
  const records = live ? controllerNodes(inventory?.nodes ?? []) : persistedNodes()
  const [transientIssue] = useState<IssuedNodeToken | null>(() => live ? liveIssuedNodeToken : null)
  const issued = live ? transientIssue : location.state as IssuedNodeToken | null
  const target = issued?.id ? nodeForId(records, issued.id) : undefined
  const issuedToken = issued?.token ?? nodeToken
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const controllerDomain = live ? new URL(controllerOrigin()).host : 'controller.example.com'

  useEffect(() => {
    if (live) liveIssuedNodeToken = null
  }, [live])

  async function copyToken() {
    try {
      await navigator.clipboard.writeText(issuedToken)
      setCopyState('copied')
    } catch {
      setCopyState('failed')
    }
  }

  if (live && !issued?.token) {
    return <div className="nodes-narrow"><EmptyState icon={<TriangleAlert />} title="Enrollment token unavailable" description="Live enrollment secrets are shown only once, immediately after issuance. Issue a new token to continue." action={<Button to="/nodes/new" variant="primary">Issue a new token</Button>} /></div>
  }

  return <div className="nodes-narrow">
    <PageHeader title="Node token issued" description={`Enroll ${issued?.name ?? 'the new node'}.`} />
    <Callout tone="warning"><strong>Copy this token now.</strong> It is shown once and expires in {issued?.expiry ?? '24 hours'}.</Callout>
    <div className="nodes-token-space">
      <TokenBox label="Enrollment token" value={issuedToken}>
        <Button onClick={copyToken} variant="secondary">{copyState === 'copied' ? <Check size={17} /> : <Clipboard size={17} />}{copyState === 'copied' ? 'Copied' : 'Copy token'}</Button>
      </TokenBox>
    </div>
    {copyState === 'failed' ? <Callout tone="danger">Clipboard access was blocked. Select the token text and copy it manually.</Callout> : null}
    <Section title="Enroll from the node" meta="Save the token in ./laneway.code with mode 0600, then run this on the Linux node.">
      <pre className="nodes-command"><code>sudo laneway node install {controllerDomain} --token-file ./laneway.code</code></pre>
    </Section>
    <div className="button-row nodes-token-actions"><Button to={target ? `/nodes/${target.id}` : '/nodes'} variant="primary">{target ? 'View node' : 'View nodes'}</Button><Button to="/nodes/new" variant="quiet">Add another node</Button></div>
  </div>
}

export function NodeDetailPage() {
  const { nodeId } = useParams()
  const { live, inventory } = useControlPlane()
  const records = live ? controllerNodes(inventory?.nodes ?? []) : persistedNodes()
  const node = nodeForId(records, nodeId)
  if (!node) return <NodeNotFound id={nodeId} />
  const controllerNode = live ? inventory?.nodes.find(record => record.node_id === node.id) : undefined
  const rawRevoked = live && controllerNode?.revoked_at_unix_seconds !== undefined
  const canEditCapabilities = live ? !rawRevoked && node.state !== 'Lease expired' : node.state !== 'Revoked'
  const canRevoke = live ? !rawRevoked : node.state !== 'Revoked'
  const change = live ? undefined : readDemoState().nodes[node.id]
  const capabilities = controllerNode ? { publish: (controllerNode.enabled_capabilities & 8) !== 0, accept: false, exit: (controllerNode.enabled_capabilities & 16) !== 0, relay: false } : change?.capabilities ?? defaultCapabilities
  const capabilityLabels = (live
    ? [capabilities.publish && 'Publish subnet routes', capabilities.exit && 'Publish default routes']
    : [capabilities.publish && 'Publish subnet routes', capabilities.accept && 'Accept routed traffic', capabilities.exit && 'Publish default routes', capabilities.relay && 'Relay fallback']).filter(Boolean)
  return <>
    <PageHeader title="Node detail" action={<Button to="/nodes">Back to nodes</Button>} />
    <DetailLayout
      identity={<IdentityBlock
        icon={nodeIcon(node.enrollmentClass)}
        title={node.name}
        state={<Status tone={node.tone}>{node.state}</Status>}
        actions={canEditCapabilities || canRevoke ? <>{canEditCapabilities ? <Button to={`/nodes/${node.id}/capabilities`} variant="secondary">Edit capabilities</Button> : null}{canRevoke ? <Button to={`/nodes/${node.id}/revoke`} variant="quiet">Revoke</Button> : null}</> : undefined}
        metadata={live
          ? [["Node ID", <code>{node.id}</code>], ["Enrollment", node.enrollmentClass], ["Created", controllerNode ? new Date(controllerNode.created_at_unix_seconds * 1000).toLocaleDateString() : '—']]
          : [["Node ID", <code>{node.id}</code>], ["Enrollment", node.enrollmentClass], ["Created", 'Aug 2, 2026'], ["Last seen", node.lastSeen]]}
      />}
    >
      <Section title="Overlay identity">
        <dl className="nodes-facts"><div><dt>IPv4</dt><dd><code>{live ? controllerNode?.ipv4_address ?? 'Not assigned' : '100.88.0.4'}</code></dd></div><div><dt>IPv6</dt><dd><code>{live ? controllerNode?.ipv6_address ?? 'Not assigned' : 'fd7a::4'}</code></dd></div>{!live ? <div><dt>Identity</dt><dd><code>lwpk_3D8K…P92M</code></dd></div> : null}</dl>
      </Section>
      {!live ? <Section title="Connectivity">
        <div className="nodes-path"><span><Status tone="positive">{node.state === 'Revoked' ? 'Authentication blocked' : 'Direct path'}</Status><small>{node.state === 'Revoked' ? 'Revoked by administrator' : '198.51.100.42:443 · 24 ms'}</small></span><span aria-hidden="true">→</span><span><Status tone={node.tone}>{node.name}</Status><small>{node.lastSeen}</small></span></div>
      </Section> : null}
      {change?.result ? <Callout>{change.result} by {change.actedBy} · {change.actedAt}</Callout> : null}
      {live && node.state === 'Lease expired' ? <Callout>The lease expired. This node can no longer authenticate.</Callout> : null}
      <Section title="Capabilities" action={canEditCapabilities ? <Button to={`/nodes/${node.id}/capabilities`} variant="quiet">Edit</Button> : undefined}>
        <div className="nodes-capabilities">{capabilityLabels.length ? capabilityLabels.map(label => <span key={label as string}><Check size={15} />{label}</span>) : <span>No capabilities enabled</span>}</div>
      </Section>
    </DetailLayout>
  </>
}

export function NodeCapabilitiesPage() {
  const { nodeId } = useParams()
  const { live, inventory, inventoryPending, request, refresh } = useControlPlane()
  const records = live ? controllerNodes(inventory?.nodes ?? []) : persistedNodes()
  const node = nodeForId(records, nodeId)
  const navigate = useNavigate()
  const controllerNode = live ? inventory?.nodes.find(record => record.node_id === node?.id) : undefined
  const savedCapabilities = live
    ? controllerNode ? controllerCapabilities(controllerNode.enabled_capabilities) : undefined
    : node ? readDemoState().nodes[node.id]?.capabilities ?? defaultCapabilities : undefined
  const [capabilities, setCapabilities] = useState<NodeCapabilities | null>(() => live ? null : savedCapabilities ?? defaultCapabilities)
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (!live || !controllerNode) return
    setCapabilities(controllerCapabilities(controllerNode.enabled_capabilities))
    setConfirmation('')
    setError('')
  }, [controllerNode?.enabled_capabilities, controllerNode?.node_id, live])

  if (live && (!inventory || (inventoryPending && !controllerNode))) return <div className="nodes-narrow" role="status">Loading node…</div>
  if (!node) return <NodeNotFound id={nodeId} />
  if (node.state === 'Revoked' || (live && (controllerNode?.revoked_at_unix_seconds !== undefined || node.state === 'Lease expired'))) return <EmptyState icon={<TriangleAlert />} title={node.state === 'Lease expired' ? 'Node lease expired' : 'Node is revoked'} description={`${node.name} cannot receive capability changes.`} action={<Button to={`/nodes/${node.id}`} variant="primary">View node</Button>} />
  if (!capabilities || !savedCapabilities) return <div className="nodes-narrow" role="status">Loading capabilities…</div>

  const activeNode: NodeRecord = node
  const activeCapabilities = capabilities
  const expected = `SAVE ${activeNode.name}`
  const changed = (Object.keys(activeCapabilities) as Array<keyof NodeCapabilities>).filter(key => activeCapabilities[key] !== savedCapabilities[key])
  const removesSubnetRole = live && savedCapabilities.publish && !activeCapabilities.publish
  const removesExitRole = live && savedCapabilities.exit && !activeCapabilities.exit
  const affectedRoutes = (inventory?.routes ?? []).filter(route =>
    route.node_id === activeNode.id
      && (route.state === 'advertised' || route.state === 'approved')
      && (!route.valid_until_unix_seconds || route.valid_until_unix_seconds > Math.floor(Date.now() / 1000))
      && ((removesSubnetRole && route.kind === 'subnet') || (removesExitRole && route.kind === 'exit')),
  )
  const affectedPrefixes = Array.from(new Set(affectedRoutes.map(route => route.prefix)))

  function toggle(key: keyof NodeCapabilities) {
    setCapabilities(current => current ? { ...current, [key]: !current[key] } : current)
    setError('')
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!live && !Object.values(activeCapabilities).some(Boolean)) {
      setError('Select at least one capability, or revoke the node instead.')
      return
    }
    if (!changed.length) {
      setError('No capability changes to save.')
      return
    }
    if (confirmation !== expected) {
      setError(`Type ${expected} exactly to apply this authorization change.`)
      return
    }
    const result = `Capabilities changed: ${changed.map(key => `${key} ${activeCapabilities[key] ? 'enabled' : 'disabled'}`).join(', ')}`
    if (live) {
      setPending(true)
      try {
        const enabledCapabilities = (activeCapabilities.publish ? 8 : 0) | (activeCapabilities.exit ? 16 : 0)
        await request(`/v1/admin/nodes/${encodeURIComponent(activeNode.id)}/capabilities`, { method: 'PUT', body: { enabled_capabilities: enabledCapabilities } })
        await refresh()
        navigate(`/nodes/${activeNode.id}`)
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : 'Unable to update node capabilities.')
      } finally {
        setPending(false)
      }
      return
    }
    updateDemoState(current => ({ ...current, nodes: { ...current.nodes, [activeNode.id]: { ...(current.nodes[activeNode.id] ?? attributed(result)), ...attributed(result), record: activeNode, capabilities: activeCapabilities } } }))
    navigate(`/nodes/${activeNode.id}`)
  }

  return <>
    <PageHeader title="Edit capabilities" />
    <div className="nodes-narrow"><FormStack onSubmit={submit}>
      <fieldset className="nodes-check-list"><legend className="sr-only">Node capabilities</legend>
        {([
          ['publish', 'Publish subnet routes', 'Advertise private IP prefixes.'],
          ['accept', 'Accept routed traffic', 'Forward approved private-network traffic.'],
          ['exit', 'Publish default routes', 'Request exit-node routing.'],
          ['relay', 'Use relay fallback', 'Use relay when direct QUIC is unavailable.'],
        ] as const).filter(([key]) => !live || key === 'publish' || key === 'exit').map(([key, label, description]) => <label className="nodes-check" key={key}><input type="checkbox" checked={activeCapabilities[key]} onChange={() => toggle(key)} /><span><strong>{label}</strong><small>{description}</small></span></label>)}
      </fieldset>
      {error ? <Callout tone="danger">{error}</Callout> : null}
      {activeCapabilities.exit ? <Callout tone="warning">Default routes can redirect broad traffic. The route still requires explicit approval before becoming active.</Callout> : null}
      {removesSubnetRole || removesExitRole ? <Callout tone="danger"><strong>Matching routes will be withdrawn.</strong>{affectedRoutes.length ? ` ${affectedRoutes.length} current route${affectedRoutes.length === 1 ? '' : 's'}: ${affectedPrefixes.join(', ')}.` : ' There are no current advertised or approved matching routes.'}</Callout> : null}
      {changed.length ? <Callout tone="warning"><strong>Exact impact:</strong> {changed.map(key => `${key} will be ${activeCapabilities[key] ? 'enabled' : 'disabled'}`).join('; ')}. This changes controller authorization for {node.name}.</Callout> : null}
      <Field label={`Type ${expected} to confirm`} error={confirmation && confirmation !== expected ? 'The confirmation phrase does not match.' : undefined}><input value={confirmation} onChange={event => { setConfirmation(event.target.value); setError('') }} autoComplete="off" /></Field>
      <div className="button-row"><Button type="submit" variant="primary" disabled={!changed.length || confirmation !== expected || pending}><ShieldCheck size={17} />{pending ? 'Saving capabilities…' : 'Save capabilities'}</Button><Button to={`/nodes/${node.id}`} variant="quiet">Cancel</Button></div>
    </FormStack></div>
  </>
}

export function NodeRevokePage() {
  const { nodeId } = useParams()
  const { live, inventory, request, refresh } = useControlPlane()
  const records = live ? controllerNodes(inventory?.nodes ?? []) : persistedNodes()
  const node = nodeForId(records, nodeId)
  const [confirmation, setConfirmation] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  if (!node) return <NodeNotFound id={nodeId} />
  const controllerNode = live ? inventory?.nodes.find(record => record.node_id === node.id) : undefined
  if (live && controllerNode?.revoked_at_unix_seconds !== undefined) return <EmptyState icon={<TriangleAlert />} title="Node is revoked" description={`${node.name} can no longer authenticate.`} action={<Button to={`/nodes/${node.id}`} variant="primary">View node</Button>} />
  const activeNode: NodeRecord = node
  const expected = activeNode.name
  const matches = confirmation === expected

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (matches) {
      if (live) {
        setPending(true)
        setError('')
        try {
          await request(`/v1/admin/nodes/${encodeURIComponent(activeNode.id)}/revoke`, { method: 'POST', body: { reason: 'Revoked from the web console' } })
          await refresh()
          setSubmitted(true)
        } catch (requestError) {
          setError(requestError instanceof Error ? requestError.message : 'Unable to revoke the node.')
        } finally {
          setPending(false)
        }
        return
      }
      const record: NodeRecord = { ...activeNode, state: 'Revoked', tone: 'danger' }
      const result = 'Node marked revoked in demo state'
      updateDemoState(current => ({ ...current, nodes: { ...current.nodes, [activeNode.id]: { ...(current.nodes[activeNode.id] ?? attributed(result)), ...attributed(result), record, capabilities: current.nodes[activeNode.id]?.capabilities ?? defaultCapabilities } } }))
      setSubmitted(true)
    }
  }

  if (submitted) return <ConfirmPanel icon={<Check />} title={live ? 'Node revoked' : 'Demo state updated'} description={live ? `The controller revoked ${node.name}'s certificates, released its overlay addresses, and withdrew its advertised and approved routes.` : 'No controller state changed.'}><Button to={`/nodes/${node.id}`} variant="primary">View node</Button></ConfirmPanel>

  return <ConfirmPanel icon={<TriangleAlert />} title={`Revoke ${node.name}?`} description={live ? 'This permanently revokes the node.' : 'This changes demo state only.'}>
    {live ? <Callout tone="danger">The controller will revoke its certificates, release its overlay addresses, and withdraw its advertised and approved routes.</Callout> : null}
    <form className="nodes-confirm-form" onSubmit={submit}>
      <Field label={`Type ${expected} to confirm`} error={confirmation && !matches ? 'The node name does not match.' : undefined}>
        <input value={confirmation} onChange={event => { setConfirmation(event.target.value); setError('') }} autoComplete="off" aria-invalid={Boolean(confirmation && !matches)} />
      </Field>
      {error ? <Callout tone="danger">{error}</Callout> : null}
      <div className="button-row"><Button type="submit" variant="danger" disabled={!matches || pending}><Trash2 size={17} />{pending ? 'Revoking node…' : 'Revoke node'}</Button><Button to={`/nodes/${node.id}`} variant="quiet">Cancel</Button></div>
    </form>
  </ConfirmPanel>
}
