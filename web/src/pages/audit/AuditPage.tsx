import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Activity, Check, Copy, Download, KeyRound, RadioTower, Route, ServerOff, ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'
import { auditEvents } from '../../lib/demo-data'
import { useControlPlane } from '../../lib/control-plane'
import { Button, FilterSelect, PageHeader, SearchField, Status, Toolbar } from '../../components/ui'
import './audit.css'

interface AuditViewRecord {
  id: string
  timestampMs: number
  time: string
  actor: string
  action: string
  actionCode: string
  target: string
  targetType: string
  targetId: string
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

export function AuditPage() {
  const { live, inventory, inventoryPending, inventoryError } = useControlPlane()
  const events = useMemo<AuditViewRecord[]>(() => (live
    ? (inventory?.auditEvents ?? []).map((event) => ({
      id: event.event_id,
      timestampMs: event.created_at_unix_seconds * 1000,
      time: new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(event.created_at_unix_seconds * 1000)),
      actor: event.actor_node_id || 'Not recorded',
      action: event.action.replaceAll('_', ' '),
      actionCode: event.action,
      target: event.target_id || event.target_type,
      targetType: event.target_type,
      targetId: event.target_id || '',
      tone: 'muted' as const,
      payload: event.details,
    }))
    : auditEvents.map((event, index) => ({
      ...event,
      timestampMs: demoTimestamps[index] ?? demoTimestamps[0],
      actionCode: detailData[event.id]?.actionCode ?? event.action.toLowerCase().replaceAll(' ', '.'),
      targetType: event.action.toLowerCase().includes('route') ? 'route' : event.action.toLowerCase().includes('node') ? 'node' : event.action.toLowerCase().includes('relay') ? 'relay' : 'credential',
      targetId: detailData[event.id]?.targetId ?? '',
      payload: detailData[event.id]?.payload ?? {},
    }))).sort((left, right) => right.timestampMs - left.timestampMs), [inventory, live])
  const [query, setQuery] = useState('')
  const [outcome, setOutcome] = useState('all')
  const [action, setAction] = useState('all')
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
      const matchesQuery = !normalized || [event.id, event.time, event.actor, event.action, event.target, event.outcome ?? ''].some((value) => value.toLowerCase().includes(normalized))
      const matchesOutcome = outcome === 'all' || event.outcome?.toLowerCase() === outcome
      const matchesAction = action === 'all' || event.action.toLowerCase().includes(action)
      const matchesRange = event.timestampMs >= cutoff
      return matchesQuery && matchesOutcome && matchesAction && matchesRange
    })
  }, [action, events, outcome, query, range])

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
    <>
      <PageHeader title="Audit events" action={<Button onClick={exportEvents} variant="secondary"><Download aria-hidden="true" size={17} /> Export JSON</Button>} />
      <Toolbar filters={<><FilterSelect label="Time range" onChange={setRange} value={range}><option value="30">Last 30 days</option><option value="7">Last 7 days</option><option value="1">Last 24 hours</option></FilterSelect>{!live ? <FilterSelect label="Outcome" onChange={setOutcome} value={outcome}><option value="all">All outcomes</option><option value="succeeded">Succeeded</option><option value="recovered">Recovered</option></FilterSelect> : null}<FilterSelect label="Action" onChange={setAction} value={action}><option value="all">Any action</option><option value="route">Route</option><option value="relay">Relay</option><option value="node">Node</option><option value="token">Token</option></FilterSelect></>}><SearchField label="Search audit events" onChange={setQuery} placeholder="Search actor, target, action, or event ID" value={query} /></Toolbar>

      {inventoryPending ? <p className="audit-message" role="status">Refreshing audit events…</p> : null}
      {inventoryError ? <p className="audit-message is-error" role="alert">Controller audit events are unavailable: {inventoryError}</p> : null}

      <div className={`audit-workspace${selected ? '' : ' is-closed'}`}>
        <section className="audit-stream" aria-label="Audit event stream">
          <div className="audit-stream-head"><span>{filteredEvents.length} events</span><span>Newest first</span></div>
          {filteredEvents.map((event) => <button aria-current={event.id === selectedId ? 'true' : undefined} className={event.id === selectedId ? 'is-selected' : undefined} key={event.id} onClick={() => { setSelectedId(event.id); setCopyState('idle') }} type="button"><time>{event.time}</time><span className={`audit-event-icon${event.tone === 'warning' ? ' is-warning' : event.tone === 'danger' ? ' is-danger' : ''}`}>{eventIcon(event.action)}</span><span><strong>{event.action}</strong><small>{event.actor} · {event.target}</small></span><code>{event.id.slice(-8)}</code></button>)}
          {!filteredEvents.length ? <div className="audit-empty"><h2>No matching events</h2><p>Change the filters or search.</p></div> : null}
        </section>

        {selected ? <aside className="audit-inspector" aria-label="Selected audit event detail"><div className="audit-inspector-head"><span className="audit-inspector-icon"><ShieldCheck aria-hidden="true" size={20} /></span><div><h2>{selected.action}</h2><p><code>{selected.id}</code></p></div>{!live ? <Status tone={selected.tone}>{selected.outcome ?? ''}</Status> : null}</div><dl><div><dt>Actor</dt><dd>{selected.actor}</dd></div><div><dt>Recorded</dt><dd>{selected.time}</dd></div><div><dt>Action</dt><dd><code>{selected.actionCode}</code></dd></div><div><dt>Target</dt><dd>{selectedTargetPath ? <Link to={selectedTargetPath}>{selected.target}</Link> : selected.target}</dd></div><div><dt>Target ID</dt><dd><code>{selected.targetId || 'Not recorded'}</code></dd></div><div><dt>Event ID</dt><dd><code>{selected.id}</code></dd></div></dl>{Object.keys(selected.payload).length ? <div className="audit-payload"><span>Recorded fields</span><pre>{JSON.stringify(selected.payload, null, 2)}</pre></div> : null}{copyState === 'error' ? <p className="audit-copy-error" role="alert">Clipboard access was blocked. Select the event ID above and copy it manually.</p> : null}<div className="button-row">{selectedTargetPath ? <Button to={selectedTargetPath} variant="primary">Open target</Button> : null}<Button onClick={copyEventId} variant="quiet">{copyState === 'copied' ? <Check aria-hidden="true" size={15} /> : <Copy aria-hidden="true" size={15} />}{copyState === 'copied' ? 'Copied' : 'Copy event ID'}</Button></div></aside> : null}
      </div>
    </>
  )
}
