import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Activity, Check, Copy, Download, KeyRound, RadioTower, Route, ServerOff, ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'
import { auditEvents } from '../../lib/demo-data'
import { useControlPlane, type ControllerAuditEvent } from '../../lib/control-plane'
import { Button, FilterSelect, PageHeader, SearchField, Status, Toolbar } from '../../components/ui'
import './audit.css'

interface AuditViewRecord {
  id: string
  timestampMs: number
  time: string
  day: string
  actor: string
  actorId: string
  action: string
  actionCode: string
  target: string
  targetType: string
  targetId: string
  scope: string
  category: 'administration' | 'network' | 'access' | 'system'
  outcome?: string
  tone: 'positive' | 'warning' | 'danger' | 'muted'
  payload: Record<string, unknown>
}

const detailData: Record<string, { timestamp: string; actionCode: string; targetId: string; payload: Record<string, string | number> }> = {
  evt_01J8APRVD42: { timestamp: 'Aug 11, 2026 at 09:42:18 UTC', actionCode: 'route.approved', targetId: 'rte_01J8PROD16', payload: { prefix: '10.24.0.0/16', connector: 'atlas-gateway', mode: 'nat', metric: 100 } },
  evt_01J8USERTOK: { timestamp: 'Aug 11, 2026 at 09:31:04 UTC', actionCode: 'user_token.issued', targetId: 'usr_01J8PLATFORM', payload: { subject: 'Platform on-call', enrollment: 'remembered', lifetime: '8h' } },
  evt_01J8RELAYFL: { timestamp: 'Aug 11, 2026 at 09:13:49 UTC', actionCode: 'relay.probe_failed', targetId: 'rly_fra02', payload: { endpoint: 'fra.example.net:443', recovery: 'direct path restored', attempts: 2 } },
  evt_01J8RENEWED: { timestamp: 'Aug 10, 2026 at 18:07:11 UTC', actionCode: 'route.renewed', targetId: 'rte_01J8PROD16', payload: { prefix: '10.24.0.0/16', lifetime: '24h', source: 'atlas-gateway' } },
  evt_01J8REVOKED: { timestamp: 'Aug 10, 2026 at 16:22:39 UTC', actionCode: 'node.revoked', targetId: 'nod_01J8CONTRACTOR', payload: { node: 'contractor-laptop', reason: 'access ended', sessionsTerminated: 1 } },
}

const demoTimestamps = [Date.UTC(2026, 7, 11, 9, 42), Date.UTC(2026, 7, 11, 9, 31), Date.UTC(2026, 7, 11, 9, 13), Date.UTC(2026, 7, 10, 18, 7), Date.UTC(2026, 7, 10, 16, 22)]

function shortId(value: string) {
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value
}

function auditDay(timestampMs: number) {
  const date = new Date(timestampMs)
  const today = new Date(); today.setHours(0, 0, 0, 0)
  const eventDay = new Date(date); eventDay.setHours(0, 0, 0, 0)
  const difference = Math.round((today.getTime() - eventDay.getTime()) / 86_400_000)
  if (difference === 0) return 'Today'
  if (difference === 1) return 'Yesterday'
  return new Intl.DateTimeFormat('en-US', { month: 'long', day: 'numeric', year: 'numeric' }).format(date)
}

export function formatControllerAuditAction(action: string) {
  const exact: Record<string, string> = {
    'administrator.login': 'Administrator signed in',
    'administrator.session.rotate': 'Administrator session renewed',
    'administrator.session.expire': 'Administrator session expired',
    'administrator.session.revoke': 'Administrator session revoked',
    'ephemeral_exit.session.start': 'Exit session started',
    'ephemeral_exit.session.stop': 'Exit session ended',
    'ephemeral_exit.lease.renew': 'Exit lease renewed',
    'ephemeral_exit.lease.expire': 'Exit lease expired',
  }
  if (exact[action]) return exact[action]
  const words = action.toLowerCase().split(/[._-]+/).filter(Boolean)
  const verb = words.pop() ?? 'recorded'
  const verbs: Record<string, string> = {
    approve: 'Approved', assign: 'Assigned', create: 'Created', delete: 'Deleted', disable: 'Disabled', enable: 'Enabled', enroll: 'Enrolled', expire: 'Expired', grant: 'Granted', issue: 'Issued', login: 'Signed in to', move: 'Moved', register: 'Registered', reject: 'Rejected', remove: 'Removed', renew: 'Renewed', revoke: 'Revoked', rotate: 'Rotated', start: 'Started', stop: 'Ended', update: 'Updated', withdraw: 'Withdrew',
  }
  const subject = words.join(' ') || 'event'
  if (verbs[verb]) return `${verbs[verb]} ${subject}`
  const label = `${subject} ${verb}`
  return `${label.charAt(0).toUpperCase()}${label.slice(1)}`
}

function eventCategory(action: string): AuditViewRecord['category'] {
  if (/(administrator|session|credential|recovery)/.test(action)) return 'administration'
  if (/(acl|access|policy|team|user|certificate)/.test(action)) return 'access'
  if (/(network|node|route|relay|exit|enrollment)/.test(action)) return 'network'
  return 'system'
}

function eventTone(action: string): AuditViewRecord['tone'] {
  if (/(fail|reject|error)/.test(action)) return 'danger'
  if (/(revoke|expire|delete|disable|withdraw)/.test(action)) return 'warning'
  if (/(create|approve|login|start|renew|enable|issue|register)/.test(action)) return 'positive'
  return 'muted'
}

function targetPath(event: AuditViewRecord) {
  if (!event.targetId) return ''
  if (event.targetType.includes('route')) return `/routes/${event.targetId}`
  if (event.targetType.includes('node')) return `/nodes/${event.targetId}`
  if (event.targetType.includes('relay')) return `/infrastructure/relays/${event.targetId}`
  return ''
}

function eventIcon(action: string): ReactNode {
  const value = action.toLowerCase()
  if (value.includes('route')) return <Route aria-hidden="true" size={16} />
  if (value.includes('relay')) return <RadioTower aria-hidden="true" size={16} />
  if (value.includes('token') || value.includes('credential')) return <KeyRound aria-hidden="true" size={16} />
  if (value.includes('revoke') || value.includes('disconnect')) return <ServerOff aria-hidden="true" size={16} />
  return <Activity aria-hidden="true" size={16} />
}

export function formatControllerAuditActor(event: Pick<ControllerAuditEvent, 'actor_kind' | 'actor_id'>) {
  switch (event.actor_kind) {
    case 'system': return 'System'
    case 'administrator': return event.actor_id ? `Administrator ${event.actor_id}` : 'Administrator'
    case 'service_principal': return event.actor_id ? `Service principal ${event.actor_id}` : 'Service principal'
    case 'recovery_grant': return event.actor_id ? `Recovery grant ${event.actor_id}` : 'Recovery grant'
    case 'node': return event.actor_id ? `Node ${event.actor_id}` : 'Node'
    case 'unauthenticated': return 'Unauthenticated'
    case 'legacy_unknown': return 'Legacy actor'
  }
}

export function AuditPage() {
  const { live, inventory, inventoryPending, inventoryError } = useControlPlane()
  const events = useMemo<AuditViewRecord[]>(() => (live
    ? (inventory?.auditEvents ?? []).map((event) => {
      const timestampMs = event.created_at_unix_seconds * 1000
      const actorNode = event.actor_id ? inventory?.nodes.find((node) => node.node_id === event.actor_id) : undefined
      const targetNode = event.target_id ? inventory?.nodes.find((node) => node.node_id === event.target_id) : undefined
      const targetNetwork = event.target_id ? inventory?.networks.find((network) => network.network_id === event.target_id) : undefined
      const targetRelay = event.target_id ? inventory?.relays.find((relay) => relay.relay_id === event.target_id) : undefined
      const targetRoute = event.target_id ? inventory?.routes.find((route) => route.route_id === event.target_id) : undefined
      const network = event.network_id ? inventory?.networks.find((candidate) => candidate.network_id === event.network_id) : undefined
      const actor = actorNode ? `Node ${actorNode.name || shortId(actorNode.node_id)}` : event.actor_id ? `${formatControllerAuditActor({ ...event, actor_id: undefined })} · ${shortId(event.actor_id)}` : formatControllerAuditActor(event)
      const target = targetNode?.name || targetNetwork?.name || targetRelay?.name || targetRoute?.prefix || (event.target_id ? `${event.target_type.replaceAll('_', ' ')} · ${shortId(event.target_id)}` : event.target_type.replaceAll('_', ' '))
      return {
        id: event.event_id,
        timestampMs,
        time: new Intl.DateTimeFormat('en-US', { hour: 'numeric', minute: '2-digit' }).format(new Date(timestampMs)),
        day: auditDay(timestampMs),
        actor,
        actorId: event.actor_id ?? '',
        action: formatControllerAuditAction(event.action),
        actionCode: event.action,
        target,
        targetType: event.target_type,
        targetId: event.target_id || '',
        scope: network?.name ?? (event.network_id ? `Network · ${shortId(event.network_id)}` : 'Global'),
        category: eventCategory(event.action),
        tone: eventTone(event.action),
        payload: event.details,
      }
    })
    : auditEvents.map((event, index) => ({
      ...event,
      timestampMs: demoTimestamps[index] ?? demoTimestamps[0],
      time: new Intl.DateTimeFormat('en-US', { hour: 'numeric', minute: '2-digit' }).format(new Date(demoTimestamps[index] ?? demoTimestamps[0])),
      day: auditDay(demoTimestamps[index] ?? demoTimestamps[0]),
      actorId: '',
      actionCode: detailData[event.id]?.actionCode ?? event.action.toLowerCase().replaceAll(' ', '.'),
      targetType: event.action.toLowerCase().includes('route') ? 'route' : event.action.toLowerCase().includes('node') ? 'node' : event.action.toLowerCase().includes('relay') ? 'relay' : 'credential',
      targetId: detailData[event.id]?.targetId ?? '',
      scope: 'Production',
      category: eventCategory(event.action),
      payload: detailData[event.id]?.payload ?? {},
    }))).sort((left, right) => right.timestampMs - left.timestampMs), [inventory, live])
  const [query, setQuery] = useState('')
  const [outcome, setOutcome] = useState('all')
  const [category, setCategory] = useState('all')
  const [range, setRange] = useState('30')
  const [selectedId, setSelectedId] = useState('')
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'error'>('idle')

  useEffect(() => {
    if (!selectedId && events[0]) setSelectedId(events[0].id)
    if (selectedId && !events.some((event) => event.id === selectedId)) setSelectedId(events[0]?.id ?? '')
  }, [events, selectedId])

  const filteredEvents = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    const rangeEnd = live ? Date.now() : events[0]?.timestampMs ?? Date.now()
    const cutoff = rangeEnd - Number(range) * 24 * 60 * 60 * 1000
    return events.filter((event) => {
      const matchesQuery = !normalized || [event.id, event.time, event.actor, event.action, event.actionCode, event.target, event.scope, event.outcome ?? ''].some((value) => value.toLowerCase().includes(normalized))
      const matchesOutcome = outcome === 'all' || event.outcome?.toLowerCase() === outcome
      const matchesCategory = category === 'all' || event.category === category
      const matchesRange = event.timestampMs >= cutoff
      return matchesQuery && matchesOutcome && matchesCategory && matchesRange
    })
  }, [category, events, live, outcome, query, range])

  const groupedEvents = useMemo(() => filteredEvents.reduce<Array<{ day: string; events: AuditViewRecord[] }>>((groups, event) => {
    const current = groups.at(-1)
    if (current?.day === event.day) current.events.push(event)
    else groups.push({ day: event.day, events: [event] })
    return groups
  }, []), [filteredEvents])

  const selected = events.find((event) => event.id === selectedId)

  function exportEvents() {
    const blob = new Blob([JSON.stringify(filteredEvents, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'laneway-audit-events.json'
    anchor.click()
    URL.revokeObjectURL(url)
  }

  async function copyEventId() {
    if (!selected) return
    try { await navigator.clipboard.writeText(selected.id); setCopyState('copied') } catch { setCopyState('error') }
  }

  const selectedTargetPath = selected ? targetPath(selected) : ''

  return (
    <div className="audit-page">
      <PageHeader title="Audit log" action={<Button onClick={exportEvents} variant="secondary"><Download aria-hidden="true" size={17} /> Export</Button>} />
      <Toolbar filters={<><FilterSelect label="Time range" onChange={setRange} value={range}><option value="30">Last 30 days</option><option value="7">Last 7 days</option><option value="1">Last 24 hours</option></FilterSelect>{!live ? <FilterSelect label="Outcome" onChange={setOutcome} value={outcome}><option value="all">All outcomes</option><option value="succeeded">Succeeded</option><option value="recovered">Recovered</option></FilterSelect> : null}<FilterSelect label="Event category" onChange={setCategory} value={category}><option value="all">All activity</option><option value="administration">Administration</option><option value="network">Network</option><option value="access">Access</option><option value="system">System</option></FilterSelect></>}><SearchField label="Search audit events" onChange={setQuery} placeholder="Search activity, actor, target, or ID" value={query} /></Toolbar>

      {inventoryPending ? <p className="audit-message" role="status">Refreshing audit events…</p> : null}
      {inventoryError ? <p className="audit-message is-error" role="alert">Controller audit events are unavailable: {inventoryError}</p> : null}

      <div className={`audit-workspace${selected ? '' : ' is-closed'}`}>
        <section className="audit-stream" aria-label="Audit event stream">
          <div className="audit-stream-head"><span>{filteredEvents.length} events</span><span>Newest first</span></div>
          <div className="audit-stream-scroll">
            {groupedEvents.map((group) => <div className="audit-day" key={group.day}><h2>{group.day}</h2>{group.events.map((event) => <button aria-current={event.id === selectedId ? 'true' : undefined} className={event.id === selectedId ? 'is-selected' : undefined} key={event.id} onClick={() => { setSelectedId(event.id); setCopyState('idle') }} type="button"><time>{event.time}</time><span className={`audit-event-icon${event.tone === 'warning' ? ' is-warning' : event.tone === 'danger' ? ' is-danger' : ''}`}>{eventIcon(event.actionCode)}</span><span><strong>{event.action}</strong><small>{event.actor} · {event.target}</small></span><em>{event.scope}</em></button>)}</div>)}
            {!filteredEvents.length ? <div className="audit-empty"><h2>No matching events</h2><p>Change the filters or search.</p></div> : null}
          </div>
        </section>

        {selected ? <aside className="audit-inspector" aria-label="Selected audit event detail"><div className="audit-inspector-head"><span className="audit-inspector-icon"><ShieldCheck aria-hidden="true" size={20} /></span><div><h2>{selected.action}</h2><p>{selected.scope}</p></div>{!live ? <Status tone={selected.tone}>{selected.outcome ?? ''}</Status> : null}</div><dl><div><dt>Actor</dt><dd>{selected.actor}</dd></div>{selected.actorId ? <div><dt>Actor ID</dt><dd><code>{selected.actorId}</code></dd></div> : null}<div><dt>Recorded</dt><dd>{selected.day} at {selected.time}</dd></div><div><dt>Action code</dt><dd><code>{selected.actionCode}</code></dd></div><div><dt>Target</dt><dd>{selectedTargetPath ? <Link to={selectedTargetPath}>{selected.target}</Link> : selected.target}</dd></div><div><dt>Target ID</dt><dd><code>{selected.targetId || 'Not recorded'}</code></dd></div><div><dt>Event ID</dt><dd><code>{selected.id}</code></dd></div></dl>{Object.keys(selected.payload).length ? <div className="audit-payload"><span>Recorded fields</span><pre>{JSON.stringify(selected.payload, null, 2)}</pre></div> : null}{copyState === 'error' ? <p className="audit-copy-error" role="alert">Clipboard access was blocked. Select the event ID above and copy it manually.</p> : null}<div className="button-row">{selectedTargetPath ? <Button to={selectedTargetPath} variant="primary">Open target</Button> : null}<Button onClick={copyEventId} variant="quiet">{copyState === 'copied' ? <Check aria-hidden="true" size={15} /> : <Copy aria-hidden="true" size={15} />}{copyState === 'copied' ? 'Copied' : 'Copy event ID'}</Button></div></aside> : null}
      </div>
    </div>
  )
}
