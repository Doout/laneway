import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Ban, CheckCircle2, ChevronRight, CircleHelp, ShieldCheck, Users } from 'lucide-react'
import { Button, Callout, ChoiceGroup, Field, FormStack, PageHeader, RecordList, ReviewPanel, SearchField, Status } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'
import { isCanonicalIpPrefix } from '../../lib/ip-prefix'
import { ErrorMessage, Missing, VisibilityToolbar, accessRulePresentation, accessRuleSummary, ipv4PrefixSelector, aclRuleLabel, selectorDestination, selectorProtocol, selectorSource, validPorts, type RecordVisibility } from './shared'
import '../traffic-workspace.css'

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
  const visibleScope = records.filter((rule) => visibility === 'all' || rule.enabled)
  const decisionOptions = [
    { id: 'all' as const, label: 'All rules', count: visibleScope.length },
    { id: 'accept' as const, label: 'Allowed', count: visibleScope.filter((rule) => rule.action === 'accept').length },
    { id: 'deny' as const, label: 'Blocked', count: visibleScope.filter((rule) => rule.action === 'deny').length },
  ]
  return <div className="traffic-workspace">
    <PageHeader title="Access" action={<div className="button-row">
      <Button to="/users" variant="quiet"><Users aria-hidden="true" size={16} />People and teams</Button>
      {networkId && hasPermission('acl.manage', networkId) ? <Button to="/access/new" variant="primary"><ShieldCheck aria-hidden="true" size={16} />Add traffic rule</Button> : null}
    </div>} />
    <div className="traffic-views" role="group" aria-label="Traffic rule views">{decisionOptions.map((option) => (
      <button key={option.id} type="button" aria-pressed={decision === option.id} onClick={() => setDecision(option.id)}>{option.label}<small>{option.count}</small></button>
    ))}</div>
    <section className="traffic-list" aria-label="Traffic rule inventory">
      <VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Enabled only" visible={visibleRecords.length} total={records.length}><SearchField label="Search access rules" placeholder="Search name, destination, or service" value={query} onChange={setQuery} /></VisibilityToolbar>
      {visibleRecords.length ? <>
        <div className="traffic-list__head" aria-hidden="true"><span>Traffic rule</span><span>Evaluation order</span><span>State</span></div>
        <ul>{visibleRecords.map((rule) => {
          const presentation = accessRulePresentation(rule)
          return <li key={rule.rule_id}><Link className="traffic-row" to={`/access/${rule.rule_id}`}>
            <span className="traffic-row__identity">
              {rule.action === 'accept' ? <CheckCircle2 className="is-allow" aria-hidden="true" size={16} /> : <Ban className="is-block" aria-hidden="true" size={16} />}
              <span><strong>{presentation.title}</strong><small>{presentation.detail}</small></span>
            </span>
            <span className="traffic-row__fact"><strong>Priority {rule.priority}</strong><small>{rule.action === 'accept' ? 'Allow traffic' : 'Block traffic'}</small></span>
            <span className="traffic-row__state"><Status tone={rule.enabled ? 'positive' : 'muted'}>{rule.enabled ? 'Enabled' : 'Disabled'}</Status></span>
            <span className="traffic-row__end">Details<ChevronRight aria-hidden="true" size={15} /></span>
          </Link></li>
        })}</ul>
      </> : <p className="traffic-list__empty">{records.length ? 'No traffic rules match this view.' : 'No traffic rules configured.'}</p>}
    </section>
  </div>
}

export function AccessDetailPage() {
  const { ruleId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const rule = inventory?.aclRules.find((candidate) => candidate.rule_id === ruleId)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  if (!rule) return <Missing title="Access rule not found" back="/access" />
  const activeRule = rule
  const presentation = accessRulePresentation(rule)
  const canManage = hasPermission('acl.manage', rule.network_id)
  async function toggle() {
    if (pending) return
    setPending(true)
    setError('')
    try {
      await request(`/v1/admin/acl-rules/${activeRule.rule_id}`, {
        method: 'PUT',
        body: { priority: activeRule.priority, action: activeRule.action, selector: activeRule.selector, description: activeRule.description, enabled: !activeRule.enabled },
      })
      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Rule update failed.')
    } finally {
      setPending(false)
    }
  }
  return <div className="traffic-workspace">
    <PageHeader title={presentation.title} action={<Button to="/access" variant="quiet">All rules</Button>} />
    <div className="traffic-layout">
      <div className="traffic-content">
        <section aria-labelledby="traffic-match-heading">
          <h2 className="traffic-section-heading" id="traffic-match-heading">Traffic match</h2>
          <RecordList rows={[
            ['From', selectorSource(rule)],
            ['To', selectorDestination(rule)],
            ['Service', selectorProtocol(rule)],
          ]} />
        </section>
        <details className="advanced-settings"><summary>Technical selector</summary><pre>{JSON.stringify(rule.selector, null, 2)}</pre></details>
        {canManage ? <section aria-labelledby="rule-availability">
          <h2 className="traffic-section-heading" id="rule-availability">Rule availability</h2>
          <ErrorMessage value={error} />
          <Button variant={rule.enabled ? 'danger' : 'primary'} disabled={pending} onClick={() => void toggle()}>{pending ? 'Updating…' : rule.enabled ? 'Disable rule' : 'Enable rule'}</Button>
        </section> : null}
      </div>
      <aside className="traffic-inspector"><ReviewPanel title="Rule information" rows={[
        ['Decision', <span className={`policy-action is-${rule.action}`}>{rule.action === 'accept' ? 'Allow' : 'Block'}</span>],
        ['State', <Status tone={rule.enabled ? 'positive' : 'muted'}>{rule.enabled ? 'Enabled' : 'Disabled'}</Status>],
        ['Evaluation priority', rule.priority],
        ['Rule ID', <code>{rule.rule_id}</code>],
      ]} /></aside>
    </div>
  </div>
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
  const [pending, setPending] = useState(false)
  const portExpression = ports
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending || !inventory?.network) return
    if (description.trim().length < 4) return setError('Enter a rule name with at least 4 characters.')
    if (!isCanonicalIpPrefix(destination, { family: 'ipv4' })) return setError('Enter a canonical IPv4 destination prefix.')
    if ((protocol === 'TCP' || protocol === 'UDP') && !validPorts(portExpression)) return setError('Choose valid ports from 1 to 65535.')
    if (action === 'accept' && !confirmed) return setError('Confirm the traffic this rule will allow.')
    setPending(true)
    setError('')
    try {
      const created = await request<{ rule_id: string }>(`/v1/admin/networks/${inventory.network.network_id}/acl-rules`, {
        method: 'POST',
        body: { description: description.trim(), priority: Number(priority), action, selector: ipv4PrefixSelector(destination, protocol, portExpression) },
      })
      await refresh()
      navigate(`/access/${created.rule_id}`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Rule creation failed.')
    } finally {
      setPending(false)
    }
  }
  const service = protocol === 'ANY' ? 'Any service' : `${protocol}${(protocol === 'TCP' || protocol === 'UDP') && portExpression.trim() ? ` on ${portExpression}` : ''}`
  return <div className="traffic-workspace">
    <PageHeader title="Add traffic rule" />
    <div className="traffic-layout traffic-form">
      <div>
        <FormStack onSubmit={submit}>
          <Field label="Rule name"><input placeholder="Allow HTTPS to production services" value={description} onChange={(event) => setDescription(event.target.value)} autoFocus /></Field>
          <ChoiceGroup label="Action" value={action} onChange={(value) => { setAction(value as typeof action); setConfirmed(false); setError('') }} options={[{ value: 'accept', label: 'Allow traffic' }, { value: 'deny', label: 'Block traffic' }]} />
          <section aria-labelledby="traffic-match-fields">
            <h2 className="traffic-section-heading" id="traffic-match-fields">Traffic match</h2>
            <div className="traffic-action-panel">
              <Field label="IPv4 prefix" hint="Destination in CIDR notation."><input placeholder="10.24.0.0/16" value={destination} onChange={(event) => setDestination(event.target.value)} spellCheck={false} /></Field>
              <div className="traffic-fields">
                <Field label="Protocol"><select value={protocol} onChange={(event) => setProtocol(event.target.value as typeof protocol)}><option value="TCP">TCP</option><option value="UDP">UDP</option><option value="ICMP">ICMP</option><option value="ANY">Any</option></select></Field>
                {protocol === 'TCP' || protocol === 'UDP' ? <Field label={<span className="field-label-with-help">Destination ports <span className="field-help" tabIndex={0} aria-label="Port format help" aria-describedby="destination-port-format"><CircleHelp aria-hidden="true" size={14} /><span id="destination-port-format" className="field-help__tooltip" role="tooltip">Use 443 for one port, 80, 443 for several, or 8000-8100 for a range.</span></span></span>}><input aria-label="Destination ports" value={ports} onChange={(event) => setPorts(event.target.value)} placeholder="443, 80, 443, or 8000-8100" inputMode="numeric" spellCheck={false} /></Field> : null}
              </div>
            </div>
          </section>
          <details className="advanced-settings"><summary>Evaluation order</summary><Field label="Priority" hint="Lower numbers run first."><input type="number" min="0" max="4294967295" value={priority} onChange={(event) => setPriority(event.target.value)} /></Field></details>
          {action === 'accept' ? <label className="decision-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span><strong>Confirm allowed traffic</strong></span></label> : <Callout>Stops matching traffic at this priority.</Callout>}
          <ErrorMessage value={error} />
          <div className="button-row"><Button type="submit" variant="primary" disabled={pending}>{pending ? 'Creating…' : 'Create rule'}</Button><Button to="/access" variant="quiet">Cancel</Button></div>
        </FormStack>
      </div>
      <aside><ReviewPanel title="Rule preview" rows={[
        ['Decision', <span className={`policy-action is-${action}`}>{action === 'accept' ? 'Allow' : 'Block'}</span>],
        ['From', 'Any enrolled node'],
        ['To', <code>{destination || 'Choose a destination'}</code>],
        ['Service', service],
        ['Priority', priority || 'Not set'],
      ]} /></aside>
    </div>
  </div>
}
