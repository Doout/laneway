import { useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowRight, Ban, CheckCircle2, CircleHelp, LockKeyhole, ShieldCheck, Users } from 'lucide-react'
import { Button, Callout, ChoiceGroup, Field, FormLayout, FormStack, PageHeader, RecordList, ReviewPanel, SearchField, Status } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'
import { isCanonicalIpPrefix } from '../../lib/ip-prefix'
import { ErrorMessage, Missing, VisibilityToolbar, accessRulePresentation, accessRuleSummary, ipv4PrefixSelector, aclRuleLabel, selectorDestination, selectorProtocol, selectorSource, validPorts, type RecordVisibility } from './shared'

export function AccessPage() {
  const { inventory, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const records = inventory?.aclRules ?? []
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const [decision, setDecision] = useState<'all' | 'accept' | 'deny'>('all')
  const [query, setQuery] = useState('')
  const normalizedQuery = query.trim().toLowerCase()
  const visibleRecords = [...records].sort((left, right) => left.priority - right.priority).filter((rule) => {
    const presentation = accessRulePresentation(rule)
    const queryMatch = !normalizedQuery || [aclRuleLabel(rule), presentation.title, presentation.detail, accessRuleSummary(rule), rule.action, String(rule.priority)].some((value) => value.toLowerCase().includes(normalizedQuery))
    return (visibility === 'all' || rule.enabled) && (decision === 'all' || rule.action === decision) && queryMatch
  })
  const allowCount = records.filter((rule) => rule.enabled && rule.action === 'accept').length
  const denyCount = records.filter((rule) => rule.enabled && rule.action === 'deny').length
  return <>
    <PageHeader title="Access" action={networkId && hasPermission('acl.manage', networkId) ? <Button to="/access/new" variant="primary"><ShieldCheck size={16} />Add traffic rule</Button> : undefined} />
    <div className="access-model">
      <div><span className="access-model__icon is-people" aria-hidden="true"><Users size={19} /></span><span><strong>People and teams</strong><small>Who can connect</small></span><Button to="/users" variant="quiet">Manage <ArrowRight size={14} /></Button></div>
      <div><span className="access-model__icon" aria-hidden="true"><ShieldCheck size={19} /></span><span><strong>Traffic rules</strong><small>What they can reach</small></span></div>
    </div>
    <nav className="decision-switcher" aria-label="Traffic rule views">
      <button type="button" aria-pressed={decision === 'all'} onClick={() => setDecision('all')}><span>All rules</span><strong>{records.filter((rule) => rule.enabled).length}</strong></button>
      <button type="button" aria-pressed={decision === 'accept'} onClick={() => setDecision('accept')}><CheckCircle2 size={16} aria-hidden="true" /><span>Allowed</span><strong>{allowCount}</strong></button>
      <button type="button" aria-pressed={decision === 'deny'} onClick={() => setDecision('deny')}><Ban size={16} aria-hidden="true" /><span>Blocked</span><strong>{denyCount}</strong></button>
    </nav>
    <div className="guided-list access-policy-list">
      <VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Enabled only" visible={visibleRecords.length} total={records.length}><SearchField label="Search access rules" placeholder="Search name, destination, or service" value={query} onChange={setQuery} /></VisibilityToolbar>
      {visibleRecords.length ? <div className="guided-list__rows">{visibleRecords.map((rule, index) => {
        const presentation = accessRulePresentation(rule)
        return <article className="guided-row access-policy-row" key={rule.rule_id}>
          <span className={`guided-row__icon is-${rule.action}`} aria-hidden="true">{rule.action === 'accept' ? <CheckCircle2 size={19} /> : <Ban size={19} />}</span>
          <div className="guided-row__identity"><small>{rule.action === 'accept' ? 'Allow traffic' : 'Block traffic'}</small><strong>{presentation.title}</strong><span>{presentation.detail}</span></div>
          <div className="guided-row__fact"><small>Evaluated</small><strong>{index === 0 ? 'First' : `Step ${index + 1}`}</strong><span>Priority {rule.priority}</span></div>
          <div className="guided-row__fact"><small>Status</small><Status tone={rule.enabled ? 'positive' : 'muted'}>{rule.enabled ? 'Enabled' : 'Disabled'}</Status></div>
          <Button to={`/access/${rule.rule_id}`} variant="quiet">Details</Button>
        </article>
      })}</div> : <div className="guided-list__empty"><LockKeyhole aria-hidden="true" /><strong>No traffic rules</strong></div>}
    </div>
  </>
}

export function AccessDetailPage() {
  const { ruleId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const rule = inventory?.aclRules.find((candidate) => candidate.rule_id === ruleId)
  const [error, setError] = useState('')
  if (!rule) return <Missing title="Access rule not found" back="/access" />
  const activeRule = rule
  const presentation = accessRulePresentation(rule)
  const canManage = hasPermission('acl.manage', rule.network_id)
  async function toggle() { try { await request(`/v1/admin/acl-rules/${activeRule.rule_id}`, { method: 'PUT', body: { priority: activeRule.priority, action: activeRule.action, selector: activeRule.selector, description: activeRule.description, enabled: !activeRule.enabled } }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Rule update failed.') } }
  return <><PageHeader title={presentation.title} action={<Button to="/access">All rules</Button>} /><div className={`detail-hero access-rule-hero is-${rule.action}`}><span className="detail-hero__icon" aria-hidden="true">{rule.action === 'accept' ? <CheckCircle2 /> : <Ban />}</span><div><h2>{selectorSource(rule)} → {selectorDestination(rule)}</h2></div><Status tone={rule.enabled ? 'positive' : 'muted'}>{rule.enabled ? 'Enabled' : 'Disabled'}</Status></div><RecordList rows={[["From", selectorSource(rule)], ["To", selectorDestination(rule)], ["Service", selectorProtocol(rule)], ["Evaluation priority", rule.priority], ["Rule ID", <code>{rule.rule_id}</code>]]} /><details className="advanced-settings rule-technical-details"><summary>Technical selector</summary><pre>{JSON.stringify(rule.selector, null, 2)}</pre></details><ErrorMessage value={error} />{canManage ? <Button variant={rule.enabled ? 'danger' : 'primary'} onClick={() => void toggle()}>{rule.enabled ? 'Disable rule' : 'Enable rule'}</Button> : null}</>
}

export function CreateAccessPage() {
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const [description, setDescription] = useState('')
  const suggestedPriority = (inventory?.aclRules.length ?? 0) ? Math.max(...(inventory?.aclRules ?? []).map((rule) => rule.priority)) + 10 : 100
  const [priority, setPriority] = useState(String(suggestedPriority))
  const [action, setAction] = useState<'accept' | 'deny'>('accept')
  const [destination, setDestination] = useState('')
  const [protocol, setProtocol] = useState<'ANY' | 'TCP' | 'UDP' | 'ICMP'>('TCP')
  const [ports, setPorts] = useState('443')
  const [confirmed, setConfirmed] = useState(false)
  const [error, setError] = useState('')
  const portExpression = ports
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!inventory?.network) return
    if (description.trim().length < 4) return setError('Enter a rule name with at least 4 characters.')
    if (!isCanonicalIpPrefix(destination, { family: 'ipv4' })) return setError('Enter a canonical IPv4 destination prefix.')
    if ((protocol === 'TCP' || protocol === 'UDP') && !validPorts(portExpression)) return setError('Choose valid ports from 1 to 65535.')
    if (action === 'accept' && !confirmed) return setError('Confirm the traffic this rule will allow.')
    try { const created = await request<{ rule_id: string }>(`/v1/admin/networks/${inventory.network.network_id}/acl-rules`, { method: 'POST', body: { description: description.trim(), priority: Number(priority), action, selector: ipv4PrefixSelector(destination, protocol, portExpression) } }); await refresh(); navigate(`/access/${created.rule_id}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Rule creation failed.') }
  }
  const service = protocol === 'ANY' ? 'Any service' : `${protocol}${(protocol === 'TCP' || protocol === 'UDP') && portExpression.trim() ? ` on ${portExpression}` : ''}`
  return <><PageHeader title="Add traffic rule" action={<Button to="/access" variant="quiet">Cancel</Button>} /><FormLayout form={<FormStack onSubmit={submit}>
    <ChoiceGroup label="Action" value={action} onChange={(value) => { setAction(value as typeof action); setConfirmed(false); setError('') }} options={[{ value: 'accept', label: 'Allow traffic' }, { value: 'deny', label: 'Block traffic' }]} />
    <Field label="Rule name"><input placeholder="Allow HTTPS to production services" value={description} onChange={(event) => setDescription(event.target.value)} autoFocus /></Field>
    <section className="traffic-builder" aria-labelledby="traffic-destination-heading"><div><span className="traffic-builder__step">1</span><span><strong id="traffic-destination-heading">Destination</strong></span></div><Field label="IPv4 prefix"><input placeholder="10.24.0.0/16" value={destination} onChange={(event) => setDestination(event.target.value)} spellCheck={false} /></Field></section>
    <section className="traffic-builder" aria-labelledby="traffic-service-heading"><div><span className="traffic-builder__step">2</span><span><strong id="traffic-service-heading">Service</strong></span></div><div className="compact-choice-group"><ChoiceGroup label="Protocol" value={protocol} onChange={(value) => setProtocol(value as typeof protocol)} options={[{ value: 'TCP', label: 'TCP' }, { value: 'UDP', label: 'UDP' }, { value: 'ICMP', label: 'ICMP' }, { value: 'ANY', label: 'Any' }]} /></div>{protocol === 'TCP' || protocol === 'UDP' ? <div className="port-builder"><Field label={<span className="field-label-with-help">Destination ports <span className="field-help" tabIndex={0} aria-label="Port format help" aria-describedby="destination-port-format"><CircleHelp aria-hidden="true" size={14} /><span id="destination-port-format" className="field-help__tooltip" role="tooltip">Use 443 for one port, 80, 443 for several, or 8000-8100 for a range.</span></span></span>}><input aria-label="Destination ports" value={ports} onChange={(event) => setPorts(event.target.value)} placeholder="443, 80, 443, or 8000-8100" inputMode="numeric" spellCheck={false} /></Field></div> : null}</section>
    <details className="advanced-settings"><summary>Evaluation order</summary><Field label="Priority" hint="Lower numbers run first."><input type="number" min="0" max="4294967295" value={priority} onChange={(event) => setPriority(event.target.value)} /></Field></details>
    {action === 'accept' ? <label className="decision-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span><strong>Confirm allowed traffic</strong></span></label> : <Callout>Stops matching traffic at this point.</Callout>}
    <ErrorMessage value={error} /><div className="button-row"><Button type="submit" variant="primary">Create rule</Button><Button to="/access">Cancel</Button></div>
  </FormStack>} review={<ReviewPanel title="Review" rows={[["Decision", <span className={`policy-action is-${action}`}>{action === 'accept' ? 'Allow' : 'Block'}</span>], ["From", 'Any enrolled node'], ["To", <code>{destination || 'Choose a destination'}</code>], ["Service", service], ["Priority", priority || 'Not set']]} />} /></>
}
