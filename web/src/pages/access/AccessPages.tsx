import { useMemo, useState, type FormEvent } from 'react'
import { Braces, CheckCircle2, FileKey2, ShieldCheck, ShieldX, SlidersHorizontal } from 'lucide-react'
import { useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  Button,
  Callout,
  ChoiceGroup,
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
  Section,
  SearchField,
  Status,
  Toolbar,
} from '../../components/ui'
import { type AccessRuleRecord } from '../../lib/demo-data'
import { useControlPlane, type ControllerACLRule } from '../../lib/control-plane'
import { isCanonicalIpPrefix } from '../../lib/ip-prefix'
import { controllerRules } from '../../lib/live-records'
import { attributed, persistedAccessRules, readDemoState, updateDemoState } from '../../lib/persisted-demo-state'
import './access-pages.css'

type RuleFormState = {
  description: string
  priority: string
  action: 'accept' | 'deny'
  source: string
  destination: string
  protocol: 'TCP' | 'UDP' | 'ICMP'
  ports: string
  confirmed: boolean
}

type RuleFormErrors = Partial<Record<keyof RuleFormState, string>>

const defaultRule: RuleFormState = {
  description: '',
  priority: '200',
  action: 'accept',
  source: 'nod_01J8OPS7F3A',
  destination: '10.24.0.0/16',
  protocol: 'TCP',
  ports: '443',
  confirmed: false,
}

function isValidPorts(value: string) {
  if (!value.trim()) return true
  return value.split(',').every(part => {
    const [first, last, extra] = part.trim().split('-')
    if (!/^\d+$/.test(first) || extra !== undefined) return false
    const start = Number(first)
    if (start < 1 || start > 65535) return false
    if (last === undefined) return true
    if (!/^\d+$/.test(last)) return false
    const end = Number(last)
    return end >= start && end <= 65535
  })
}

function controllerSelector(form: RuleFormState) {
  const [address, prefixLength] = form.destination.trim().split('/')
  const octets = address.split('.').map(Number)
  if (octets.length !== 4 || octets.some(value => !Number.isInteger(value) || value < 0 || value > 255)) {
    throw new Error('Live controller rule creation currently supports IPv4 destination prefixes from this form.')
  }
  const selector: Record<string, unknown> = {
    destination_prefixes: [{ address: btoa(String.fromCharCode(...octets)), prefix_length: Number(prefixLength) }],
    ip_protocol: `IP_PROTOCOL_${form.protocol}`,
  }
  if (form.protocol !== 'ICMP' && form.ports.trim()) {
    selector.destination_ports = form.ports.split(',').map(value => {
      const [first, last] = value.trim().split('-').map(Number)
      return { first, last: last ?? first }
    })
  }
  return selector
}

function controllerRuleForm(rule: AccessRuleRecord, source?: ControllerACLRule): RuleFormState {
  const selector = source?.selector ?? {}
  const prefixes = Array.isArray(selector.destination_prefixes) ? selector.destination_prefixes as Array<Record<string, unknown>> : []
  const firstPrefix = prefixes[0]
  let destination = '10.24.0.0/16'
  if (firstPrefix && typeof firstPrefix.address === 'string' && typeof firstPrefix.prefix_length === 'number') {
    try {
      const bytes = Array.from(atob(firstPrefix.address), character => character.charCodeAt(0))
      if (bytes.length === 4) destination = `${bytes.join('.')}/${firstPrefix.prefix_length}`
    } catch { /* Keep the safe visible fallback when controller bytes cannot be decoded. */ }
  }
  const protocolValue = typeof selector.ip_protocol === 'string' ? selector.ip_protocol.replace('IP_PROTOCOL_', '') : 'TCP'
  const protocol = ['TCP', 'UDP', 'ICMP'].includes(protocolValue) ? protocolValue as RuleFormState['protocol'] : 'TCP'
  const ports = Array.isArray(selector.destination_ports) ? (selector.destination_ports as Array<Record<string, unknown>>).map(port => port.first === port.last ? String(port.first) : `${port.first}-${port.last}`).join(', ') : ''
  return { description: rule.name, priority: String(rule.priority), action: rule.action === 'Allow' ? 'accept' : 'deny', source: 'any', destination, protocol, ports, confirmed: false }
}

function ruleForId(id?: string, records = persistedAccessRules()) {
  return records.find(rule => rule.id === id || rule.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') === id)
}

function RuleNotFound({ id }: { id?: string }) {
  return <EmptyState icon={<SlidersHorizontal />} title="Access rule not found" description={`No access rule matches ${id ? `“${id}”` : 'this address'}.`} action={<Button to="/access" variant="primary">Return to access rules</Button>} />
}

function displayAction(rule: AccessRuleRecord) {
  return rule.action === 'Allow' ? 'Accept' : 'Deny'
}

export function AccessRulesPage() {
  const { live, inventory } = useControlPlane()
  const records = live ? controllerRules(inventory?.aclRules ?? []) : persistedAccessRules()
  const [query, setQuery] = useState('')
  const [action, setAction] = useState('all')
  const [enabled, setEnabled] = useState('all')
  const [selectedId, setSelectedId] = useState(records[0]?.id ?? '')

  const visibleRules = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    return records.filter(rule => {
      const liveSelector = live ? inventory?.aclRules.find(record => record.rule_id === rule.id)?.selector : undefined
      const matchesQuery = !normalized || [rule.name, rule.selector, live ? JSON.stringify(liveSelector ?? {}) : rule.target].some(value => value.toLowerCase().includes(normalized))
      const matchesAction = action === 'all' || rule.action.toLowerCase() === action
      const matchesState = enabled === 'all' || rule.state.toLowerCase() === enabled
      return matchesQuery && matchesAction && matchesState
    })
  }, [action, enabled, inventory?.aclRules, live, query, records])
  const selected = visibleRules.find(rule => rule.id === selectedId) ?? visibleRules[0]
  const selectedControllerRule = live ? inventory?.aclRules.find(rule => rule.rule_id === selected?.id) : undefined
  const enabledCount = records.filter(rule => rule.state === 'Enabled').length

  return <div className="access-page">
    <PageHeader
      title="Access rules"
      action={<Button variant="primary" to="/access/new"><ShieldCheck aria-hidden="true" size={17} />New rule</Button>}
    />
    <div className="access-health-strip" aria-label="Access policy summary"><div><strong>{enabledCount}</strong><span>Enabled rules</span></div><div><strong>{records.length - enabledCount}</strong><span>Disabled rules</span></div><div><strong>{records.filter(rule => rule.action === 'Allow').length}</strong><span>Accept rules</span></div><div><strong>{live ? inventory?.network?.configuration_epoch ?? '—' : 418}</strong><span>Configuration epoch</span></div></div>
    <Toolbar filters={<>
      <div className="access-segments" aria-label="Rule action"><button className={action === 'all' ? 'is-active' : ''} onClick={() => setAction('all')}>All</button><button className={action === 'allow' ? 'is-active' : ''} onClick={() => setAction('allow')}>Accept</button><button className={action === 'deny' ? 'is-active' : ''} onClick={() => setAction('deny')}>Deny</button></div>
      <FilterSelect label="Filter by state" value={enabled} onChange={setEnabled}>
        <option value="all">All states</option>
        <option value="enabled">Enabled</option>
        <option value="disabled">Disabled</option>
      </FilterSelect>
      <span className="access-count" aria-live="polite">{visibleRules.length} shown</span>
    </>}>
      <SearchField label="Search access rules" placeholder={live ? 'Search description or selector' : 'Search description, selector, or destination'} value={query} onChange={setQuery} />
    </Toolbar>
    <div className="access-workspace"><section className="access-panel access-inventory"><DataTable
        rows={visibleRules}
        rowKey={rule => rule.id}
        columns={[
          { key: 'priority', label: 'Priority', render: rule => <span className="access-priority">{rule.priority}</span> },
          { key: 'rule', label: 'Rule', render: rule => <EntityTitle icon={rule.action === 'Allow' ? <ShieldCheck size={16} /> : <ShieldX size={16} />} subtitle={rule.id}>{rule.name}</EntityTitle> },
          { key: 'action', label: 'Action', render: rule => <span className={`access-action access-action--${rule.action.toLowerCase()}`}>{displayAction(rule)}</span> },
          { key: 'source', label: live ? 'Selector' : 'Subject', render: rule => <code>{live ? JSON.stringify(inventory?.aclRules.find(record => record.rule_id === rule.id)?.selector ?? {}) : rule.selector}</code> },
          { key: 'destination', label: live ? 'Epoch' : 'Destination', render: rule => live ? inventory?.aclRules.find(record => record.rule_id === rule.id)?.configuration_epoch ?? 'Unavailable' : rule.target },
          { key: 'state', label: 'State', render: rule => <Status tone={rule.tone}>{rule.state}</Status> },
          { key: 'actions', label: '', align: 'end', render: rule => <Button variant={selected?.id === rule.id ? 'secondary' : 'quiet'} onClick={() => setSelectedId(rule.id)}>Inspect</Button> },
        ]}
        empty={<div className="access-empty"><SlidersHorizontal aria-hidden="true" /><h2>No rules match</h2><p>Clear a filter or search for a different selector.</p></div>}
      /></section>{selected ? <aside className="access-panel access-inspector"><span className="access-panel-label">Inspector</span><h2>{selected.name}</h2><p>{displayAction(selected)} rule · priority {selected.priority}</p>{live ? <dl><div><dt>Selector</dt><dd><code>{selectedControllerRule ? JSON.stringify(selectedControllerRule.selector) : 'Unavailable'}</code></dd></div><div><dt>Network ID</dt><dd><code>{selectedControllerRule?.network_id ?? 'Unavailable'}</code></dd></div><div><dt>State</dt><dd><Status tone={selected.tone}>{selected.state}</Status></dd></div><div><dt>Epoch</dt><dd>{selectedControllerRule?.configuration_epoch ?? 'Unavailable'}</dd></div></dl> : <dl><div><dt>Subject</dt><dd><code>{selected.selector}</code></dd></div><div><dt>Destination</dt><dd>{selected.target}</dd></div><div><dt>State</dt><dd><Status tone={selected.tone}>{selected.state}</Status></dd></div><div><dt>Epoch</dt><dd>418</dd></div></dl>}<div className="button-row"><Button variant="primary" to={`/access/${selected.id}`}>Open rule</Button></div></aside> : null}</div>
  </div>
}

export function AccessRuleFormPage() {
  const { live, inventory, request, refresh } = useControlPlane()
  const { ruleId } = useParams()
  const navigate = useNavigate()
  const editing = Boolean(ruleId)
  const liveRecords = controllerRules(inventory?.aclRules ?? [])
  const existing = ruleForId(ruleId, live ? liveRecords : persistedAccessRules())
  const liveExisting = inventory?.aclRules.find(rule => rule.rule_id === ruleId)
  const [form, setForm] = useState<RuleFormState>(() => editing && existing ? {
    ...(live ? controllerRuleForm(existing, liveExisting) : {
      description: existing.name,
      priority: String(existing.priority),
      action: existing.action === 'Allow' ? 'accept' : 'deny',
      source: existing.id === 'acl_01J8PRODOPS' ? 'nod_01J8OPS7F3A' : 'any',
      destination: existing.target.includes('/') ? existing.target : '10.24.0.0/16',
      protocol: 'TCP' as const,
      ports: '443',
      confirmed: false,
    }),
  } : {
    ...defaultRule,
    description: live ? '' : defaultRule.description,
    source: live ? 'any' : defaultRule.source,
    destination: live ? '' : defaultRule.destination,
    ports: live ? '' : defaultRule.ports,
  })
  const [errors, setErrors] = useState<RuleFormErrors>({})
  const [submitError, setSubmitError] = useState('')
  const [pending, setPending] = useState(false)

  if (editing && !existing) return <RuleNotFound id={ruleId} />
  if (live && editing) return <EmptyState icon={<SlidersHorizontal />} title="Editing unavailable" description="Disable this rule and create a replacement." action={<Button to={`/access/${ruleId}`} variant="primary">Back to rule</Button>} />

  function update<K extends keyof RuleFormState>(key: K, value: RuleFormState[K]) {
    setForm(current => ({ ...current, [key]: value }))
    setErrors(current => ({ ...current, [key]: undefined }))
  }

  function validate() {
    const next: RuleFormErrors = {}
    if (form.description.trim().length < 4) next.description = 'Describe the intent of this rule in at least 4 characters.'
    const priority = Number(form.priority)
    if (!Number.isInteger(priority) || priority < 0 || priority > 4_294_967_295) next.priority = 'Priority must be a whole number from 0 to 4,294,967,295.'
    if (!isCanonicalIpPrefix(form.destination, live ? { family: 'ipv4' } : undefined)) next.destination = live ? 'Enter a canonical IPv4 CIDR prefix.' : 'Enter a canonical IPv4 or IPv6 CIDR prefix.'
    if ((form.protocol === 'TCP' || form.protocol === 'UDP') && !isValidPorts(form.ports)) next.ports = 'Use comma-separated ports or ranges from 1 to 65535.'
    if (form.action === 'accept' && !form.confirmed) next.confirmed = 'Confirm that you reviewed the selector and priority.'
    setErrors(next)
    return Object.keys(next).length === 0
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!validate()) return
    const savedRule: AccessRuleRecord = {
      id: ruleId ?? 'acl_preview',
      priority: Number(form.priority),
      name: form.description.trim(),
      action: form.action === 'accept' ? 'Allow' : 'Deny',
      selector: form.source === 'any' ? 'any enrolled node' : `node:${form.source}`,
      target: form.destination.trim(),
      state: 'Enabled',
      tone: 'positive',
    }
    if (live) {
      if (!inventory?.network) {
        setSubmitError('The controller has no active network. Refresh the inventory and try again.')
        return
      }
      setPending(true)
      setSubmitError('')
      try {
        const body = {
          priority: savedRule.priority,
          action: form.action,
          selector: controllerSelector(form),
          description: savedRule.name,
          ...(editing ? { enabled: liveExisting?.enabled ?? true } : {}),
        }
        const created = await request<{ rule_id: string }>(editing ? `/v1/admin/acl-rules/${ruleId}` : `/v1/admin/networks/${inventory.network.network_id}/acl-rules`, { method: editing ? 'PUT' : 'POST', body })
        await refresh()
        navigate(`/access/${created.rule_id || ruleId}`)
      } catch (error) {
        setSubmitError(error instanceof Error ? error.message : 'The controller could not create this access rule.')
      } finally {
        setPending(false)
      }
      return
    }
    const result = editing ? 'Access rule updated and queued for epoch 419' : 'Access rule created and queued for epoch 419'
    updateDemoState(current => ({ ...current, accessRules: { ...current.accessRules, [savedRule.id]: { ...attributed(result), record: savedRule } } }))
    navigate(`/access/${savedRule.id}`, { state: { saved: true, rule: savedRule } })
  }

  const sourceLabel = form.source === 'any' ? 'Any enrolled node' : form.source === 'nod_01J8OPS7F3A' ? 'ops-session-7f3a' : 'atlas-gateway'
  const protocolName = `IP_PROTOCOL_${form.protocol}`

  return <div className="access-page access-form-page">
    <PageHeader title={editing ? 'Edit access rule' : 'Create access rule'} action={<Button variant="quiet" to={editing ? `/access/${ruleId}` : '/access'}>Cancel</Button>} />
    <FormLayout
      form={<FormStack onSubmit={submit}>
        <Field label="Description" error={errors.description}>
          <input value={form.description} aria-invalid={Boolean(errors.description)} onChange={event => update('description', event.target.value)} placeholder="Allow production operators to HTTPS services" autoFocus />
        </Field>
        <Field label="Priority" hint="Lowest value runs first; ties sort by rule ID." error={errors.priority}>
          <input type="number" min="0" max="4294967295" step="1" value={form.priority} aria-invalid={Boolean(errors.priority)} onChange={event => update('priority', event.target.value)} />
        </Field>
        <ChoiceGroup label="Action" value={form.action} onChange={value => { update('action', value as RuleFormState['action']); if (value === 'deny') update('confirmed', false) }} options={[
          { value: 'accept', label: 'Accept', description: 'Allow traffic matching every field.' },
          { value: 'deny', label: 'Deny', description: 'Reject matching traffic.' },
        ]} />
        {live ? <Field label="Source node"><input value="Any enrolled node" readOnly /></Field> : <Field label="Source node" hint="Authorization uses the selected Node ID.">
          <select value={form.source} onChange={event => update('source', event.target.value)}><option value="nod_01J8OPS7F3A">ops-session-7f3a · Remembered user</option><option value="nod_01J8ATLAS9GP">atlas-gateway · Connector</option><option value="any">Any enrolled node</option></select>
        </Field>}
        <Field label="Destination prefix" hint={live ? 'Enter an IPv4 CIDR prefix.' : 'Enter an IPv4 or IPv6 CIDR prefix.'} error={errors.destination}>
          <input value={form.destination} aria-invalid={Boolean(errors.destination)} onChange={event => update('destination', event.target.value)} spellCheck={false} />
        </Field>
        <div className="access-field-grid">
          <Field label="IP protocol">
            <select value={form.protocol} onChange={event => update('protocol', event.target.value as RuleFormState['protocol'])}>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
          </Field>
          <Field label="Destination ports" hint={form.protocol === 'ICMP' ? 'Ports do not apply to ICMP.' : 'Optional; comma-separated ports or ranges.'} error={errors.ports}>
            <input disabled={form.protocol === 'ICMP'} value={form.protocol === 'ICMP' ? '' : form.ports} aria-invalid={Boolean(errors.ports)} onChange={event => update('ports', event.target.value)} placeholder="443, 8443-8450" />
          </Field>
        </div>
        {form.action === 'accept' ? <>
          <Callout tone="warning"><strong>Accept rule</strong><br />Matching packets are accepted when every configured selector field matches. Priority determines evaluation order.</Callout>
          <label className="access-confirm">
            <input type="checkbox" checked={form.confirmed} onChange={event => update('confirmed', event.target.checked)} />
            <span>I reviewed the selector and priority.</span>
          </label>
          {errors.confirmed ? <p className="access-error" role="alert">{errors.confirmed}</p> : null}
        </> : <Callout><strong>Deny rule</strong><br />Matching packets are denied when every configured selector field matches. Priority determines evaluation order.</Callout>}
        {submitError ? <Callout tone="danger">{submitError}</Callout> : null}
        <div className="button-row"><Button type="submit" variant="primary" disabled={pending}>{pending ? editing ? 'Saving…' : 'Creating…' : editing ? 'Save rule' : 'Create rule'}</Button><Button variant="quiet" to={editing ? `/access/${ruleId}` : '/access'}>Cancel</Button></div>
      </FormStack>}
      review={<ReviewPanel title="Rule preview" rows={[
        ['Priority', form.priority || '—'],
        ['Action', <span className={`access-action access-action--${form.action === 'accept' ? 'allow' : 'deny'}`}>{form.action === 'accept' ? 'Accept' : 'Deny'}</span>],
        ['Source', sourceLabel],
        ['Destination', <code>{form.destination || '—'}</code>],
        ['Protocol', protocolName],
        ['Ports', form.protocol === 'ICMP' ? 'Not applicable' : form.ports || 'Any'],
      ]} />}
    />
  </div>
}

export function AccessRuleDetailPage() {
  const { live, inventory, request, refresh } = useControlPlane()
  const { ruleId } = useParams()
  const location = useLocation()
  const navigate = useNavigate()
  const locationState = location.state as { saved?: boolean; rule?: AccessRuleRecord } | null
  const [, setRevision] = useState(0)
  const [showStateChange, setShowStateChange] = useState(false)
  const [confirmation, setConfirmation] = useState('')
  const [stateChangeError, setStateChangeError] = useState('')
  const [stateChangePending, setStateChangePending] = useState(false)
  const supplied = locationState?.rule
  const liveRecords = controllerRules(inventory?.aclRules ?? [])
  const resolvedRule = live ? ruleForId(ruleId, liveRecords) : (supplied && !readDemoState().accessRules[supplied.id] ? supplied : undefined) ?? ruleForId(ruleId)
  const liveRule = live ? inventory?.aclRules.find(candidate => candidate.rule_id === ruleId) : undefined

  if (!resolvedRule) return <RuleNotFound id={ruleId} />
  const rule = resolvedRule
  const saved = live ? undefined : readDemoState().accessRules[rule.id]
  const liveNetwork = live ? inventory?.networks.find(network => network.network_id === liveRule?.network_id) ?? inventory?.network : undefined

  const enabling = rule.state === 'Disabled'
  const stateChangeVerb = enabling ? 'enable' : 'disable'

  async function changeEnabledState(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (confirmation !== rule.name) {
      setStateChangeError(`Type ${rule.name} exactly to ${stateChangeVerb} this rule.`)
      return
    }
    if (live) {
      if (!liveRule) {
        setStateChangeError('The controller rule record is no longer available. Refresh the inventory and try again.')
        return
      }
      setStateChangePending(true)
      setStateChangeError('')
      try {
        await request(`/v1/admin/acl-rules/${rule.id}`, { method: 'PUT', body: {
          priority: liveRule.priority,
          action: liveRule.action,
          selector: liveRule.selector,
          description: liveRule.description,
          enabled: enabling,
        } })
        await refresh()
        navigate('/access')
      } catch (error) {
        setStateChangeError(error instanceof Error ? error.message : `The controller could not ${stateChangeVerb} this rule.`)
      } finally {
        setStateChangePending(false)
      }
      return
    }
    const record: AccessRuleRecord = { ...rule, state: enabling ? 'Enabled' : 'Disabled', tone: enabling ? 'positive' : 'muted' }
    updateDemoState(current => ({ ...current, accessRules: { ...current.accessRules, [rule.id]: { ...attributed(`Access rule ${enabling ? 'enabled' : 'disabled'} for epoch 419`), record } } }))
    setShowStateChange(false)
    setConfirmation('')
    setRevision(value => value + 1)
  }

  const action = displayAction(rule)
  return <div className="access-page access-detail-page">
    {locationState?.saved || saved?.result ? <div className="access-saved" role="status"><CheckCircle2 aria-hidden="true" size={17} />{saved?.result ?? 'Rule saved.'}</div> : null}
    <PageHeader title={rule.name} action={<div className="button-row">{live ? <Button variant="secondary" disabled title="Editing existing live selectors is unavailable.">Editing unavailable</Button> : <Button variant="secondary" to={`/access/${rule.id}/edit`}>Edit rule</Button>}<Button variant="quiet" to="/access">All rules</Button></div>} />
    <DetailLayout
      identity={<IdentityBlock
        icon={rule.action === 'Allow' ? <ShieldCheck aria-hidden="true" size={34} /> : <ShieldX aria-hidden="true" size={34} />}
        title={action}
        state={<Status tone={rule.tone}>{rule.state}</Status>}
        metadata={live ? [
          ['Rule ID', <code>{liveRule?.rule_id ?? rule.id}</code>],
          ['Priority', liveRule?.priority ?? 'Unavailable'],
          ['Network', liveNetwork?.name || liveRule?.network_id || 'Unavailable'],
          ['Network ID', <code>{liveRule?.network_id ?? 'Unavailable'}</code>],
          ['Epoch', liveRule?.configuration_epoch ?? 'Unavailable'],
        ] : [
          ['Rule ID', <code>{rule.id}</code>],
          ['Priority', rule.priority],
          ['Network', 'Production'],
          ['Updated', 'Today, 09:18 UTC'],
          ['Epoch', '418'],
        ]}
      />}
    >
      <Section title="Traffic selector" meta={!live ? 'Every populated field must match. Empty source or destination lists act as wildcards.' : undefined}>
        {live ? liveRule ? <div className="access-selector-preview"><span><Braces aria-hidden="true" size={15} />Selector JSON</span><code>{JSON.stringify(liveRule.selector)}</code></div> : <Callout tone="danger">Selector unavailable.</Callout> : <dl className="access-selector-list">
          <div><dt>Source node IDs</dt><dd><code>{rule.selector}</code></dd></div>
          <div><dt>Source prefixes</dt><dd>Any</dd></div>
          <div><dt>Destination node IDs</dt><dd>Any</dd></div>
          <div><dt>Destination prefixes</dt><dd><code>{rule.target.includes('/') ? rule.target : '10.24.0.0/16'}</code></dd></div>
          <div><dt>IP protocol</dt><dd>TCP</dd></div>
          <div><dt>Destination ports</dt><dd><code>443</code></dd></div>
        </dl>}
      </Section>
      <Section title={`${enabling ? 'Enable' : 'Disable'} rule`}>
        <Callout tone="warning"><FileKey2 aria-hidden="true" size={16} /> Rule {rule.priority} will be {enabling ? 'enabled' : 'disabled'} in the next policy epoch.</Callout>
        {showStateChange ? <form className="access-disable-form" onSubmit={changeEnabledState}>
          <Field label={`Type ${rule.name} to confirm`} error={stateChangeError || undefined}><input value={confirmation} disabled={stateChangePending} onChange={event => { setConfirmation(event.target.value); setStateChangeError('') }} autoComplete="off" /></Field>
          <div className="button-row"><Button type="submit" variant={enabling ? 'primary' : 'danger'} disabled={confirmation !== rule.name || stateChangePending}>{stateChangePending ? `${enabling ? 'Enabling' : 'Disabling'}…` : `${enabling ? 'Enable' : 'Disable'} rule`}</Button><Button variant="quiet" disabled={stateChangePending} onClick={() => { setShowStateChange(false); setConfirmation(''); setStateChangeError('') }}>Cancel</Button></div>
        </form> : <div className="access-section-action"><Button variant={enabling ? 'primary' : 'danger'} onClick={() => setShowStateChange(true)}>{enabling ? 'Enable' : 'Disable'} rule</Button></div>}
      </Section>
    </DetailLayout>
  </div>
}
