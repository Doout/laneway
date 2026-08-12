import { FormEvent, useEffect, useMemo, useState } from 'react'
import { Check, Clipboard, Clock3, KeyRound, Laptop, RotateCcw, Trash2, UserRound, Users } from 'lucide-react'
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
  SearchField,
  Section,
  Status,
  TokenBox,
  Toolbar,
} from '../../components/ui'
import { type UserEnrollmentRecord } from '../../lib/demo-data'
import { controllerOrigin, useControlPlane } from '../../lib/control-plane'
import { userEnrollmentCommand } from '../../lib/enrollment-commands'
import { controllerUsers } from '../../lib/live-records'
import { attributed, persistedUsers, readDemoState, updateDemoState } from '../../lib/persisted-demo-state'
import './users.css'

const userToken = 'lnw_user_01J8PLATFORM_7gN2mK6xV4qC'
type IssuedUserToken = { id?: string; tokenId?: string; subject?: string; enrollment?: string; networkName?: string; leaseHours?: number; token?: string }
let liveIssuedUserToken: IssuedUserToken | null = null

function userForId(id?: string, records = persistedUsers()) {
  return records.find(user => user.id === id || user.subject.toLowerCase().replace(/[^a-z0-9]+/g, '-') === id)
}

function UserNotFound({ id }: { id?: string }) {
  return <EmptyState icon={<Users />} title="User enrollment not found" description={`No enrollment matches ${id ? `“${id}”` : 'this address'}.`} action={<Button to="/users" variant="primary">Return to user access</Button>} />
}

export function UsersListPage() {
  const { live, inventory } = useControlPlane()
  const records = live ? controllerUsers(inventory?.nodes ?? [], inventory?.network?.name ?? 'Controller network') : persistedUsers()
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('all')
  const [state, setState] = useState('all')
  const [selectedId, setSelectedId] = useState(records[0]?.id ?? '')
  const filteredUsers = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return records.filter(user => {
      const matchesQuery = !needle || [user.subject, user.id, user.network].some(value => value.toLowerCase().includes(needle))
      return matchesQuery && (kind === 'all' || user.enrollment === kind) && (state === 'all' || user.state === state)
    })
  }, [kind, query, records, state])
  const selected = records.find(user => user.id === selectedId) ?? filteredUsers[0]
  const selectedControllerNode = live && selected ? inventory?.nodes.find(node => node.node_id === selected.id) : undefined
  const activeCount = records.filter(user => user.state === 'Active').length
  const ephemeralCount = records.filter(user => user.enrollment === 'Ephemeral').length

  return <div className="users-page">
    <PageHeader title="Users" action={<Button to="/users/new" variant="primary"><KeyRound size={17} />Issue access</Button>} />
    <div className="users-health-strip" aria-label="User access summary">
      <div><strong>{activeCount}</strong><span>Active enrollments</span></div><div><strong>{live ? records.length : records.reduce((total, user) => total + user.devices, 0)}</strong><span>{live ? 'Enrollment nodes' : 'Enrolled devices'}</span></div><div><strong>{ephemeralCount}</strong><span>{live ? 'Ephemeral enrollment nodes' : 'Ephemeral enrollments'}</span></div>{live ? <div><strong>{records.length - activeCount}</strong><span>Inactive enrollments</span></div> : null}
    </div>
    <div className="users-table-space">
      <Toolbar filters={<>
        <div className="users-segments" aria-label="Enrollment type"><button className={kind === 'all' ? 'is-active' : ''} onClick={() => setKind('all')}>All</button><button className={kind === 'Remembered' ? 'is-active' : ''} onClick={() => setKind('Remembered')}>Remembered</button><button className={kind === 'Ephemeral' ? 'is-active' : ''} onClick={() => setKind('Ephemeral')}>Ephemeral</button></div>
        <FilterSelect label="Filter by state" value={state} onChange={setState}><option value="all">Any state</option><option>Active</option><option>Expired</option><option>Revoked</option></FilterSelect>
        <span className="users-result-count" aria-live="polite">{filteredUsers.length} shown</span>
      </>}><SearchField label="Search user enrollments" placeholder={`Search name, network, or ${live ? 'node' : 'enrollment'} ID`} value={query} onChange={setQuery} /></Toolbar>
      <div className="users-workspace">
        <section className="users-panel users-inventory" aria-label="User access inventory"><DataTable
          rows={filteredUsers}
          rowKey={user => user.id}
          empty={<EmptyState icon={<Users />} title="No enrollments match" description="No records match the current filters." action={<Button onClick={() => { setQuery(''); setKind('all'); setState('all') }}><RotateCcw size={16} />Reset filters</Button>} />}
          columns={[
            { key: 'subject', label: 'User', render: user => <EntityTitle icon={<UserRound size={17} />} subtitle={user.id}>{user.subject}</EntityTitle> },
            { key: 'type', label: 'Enrollment', render: user => user.enrollment },
            { key: 'network', label: 'Network', render: user => user.network },
            { key: 'devices', label: live ? 'Address' : 'Devices', render: user => live ? [inventory?.nodes.find(node => node.node_id === user.id)?.ipv4_address, inventory?.nodes.find(node => node.node_id === user.id)?.ipv6_address].filter(Boolean).join(' · ') || 'Not assigned' : user.devices },
            { key: 'state', label: 'Status', render: user => <Status tone={user.tone}>{user.state}</Status> },
            { key: 'action', label: '', align: 'end', render: user => <Button onClick={() => setSelectedId(user.id)} variant={selected?.id === user.id ? 'secondary' : 'quiet'}>Inspect</Button> },
          ]}
        /></section>
        {selected ? <aside className="users-panel users-inspector"><span className="users-panel-label">Inspector</span><h2>{selected.subject}</h2><p>{selected.enrollment} enrollment · {selected.state}</p>{live ? <dl><div><dt>Node ID</dt><dd><code>{selected.id}</code></dd></div><div><dt>Network</dt><dd>{selected.network}</dd></div><div><dt>IPv4</dt><dd><code>{selectedControllerNode?.ipv4_address ?? 'Not assigned'}</code></dd></div><div><dt>IPv6</dt><dd><code>{selectedControllerNode?.ipv6_address ?? 'Not assigned'}</code></dd></div><div><dt>Lease</dt><dd>{selected.lease}</dd></div></dl> : <dl><div><dt>Enrollment ID</dt><dd><code>{selected.id}</code></dd></div><div><dt>Network</dt><dd>{selected.network}</dd></div><div><dt>Devices</dt><dd>{selected.devices}</dd></div><div><dt>Lease</dt><dd>{selected.lease}</dd></div></dl>}<div className="button-row"><Button to={`/users/${selected.id}`} variant="primary">View details</Button><Button to="/users/new" variant="quiet">Issue access</Button></div></aside> : null}
      </div>
    </div>
  </div>
}

export function IssueUserAccessPage() {
  const { live, inventory, inventoryPending, request } = useControlPlane()
  const navigate = useNavigate()
  const [subject, setSubject] = useState('')
  const [enrollment, setEnrollment] = useState('Ephemeral')
  const [networkName, setNetworkName] = useState('Production')
  const [lease, setLease] = useState('8')
  const [errors, setErrors] = useState({ subject: '', lease: '' })
  const [submitError, setSubmitError] = useState('')
  const [pending, setPending] = useState(false)
  const selectedNetworkName = live ? inventory?.network?.name ?? 'Loading controller network…' : networkName

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const leaseHours = Number(lease)
    const nextErrors = {
      subject: subject.trim().length < 2 ? 'Enter a recognizable subject label with at least 2 characters.' : '',
      lease: enrollment === 'Ephemeral' && (!Number.isInteger(leaseHours) || leaseHours < 1 || leaseHours > 24) ? 'Enter a whole number from 1 to 24.' : '',
    }
    setErrors(nextErrors)
    if (nextErrors.subject || nextErrors.lease) {
      return
    }
    if (live) {
      if (!inventory?.network) {
        setSubmitError('The controller has no active network. Refresh the inventory and try again.')
        return
      }
      setPending(true)
      setSubmitError('')
      try {
        const issued = await request<{ enrollment_token: string; token_id: string }>('/v1/admin/enrollment-tokens', { method: 'POST', body: {
          network_id: inventory.network.network_id,
          label: subject.trim(),
          requested_name: subject.trim(),
          expires_at_unix_seconds: Math.floor(Date.now() / 1000) + 900,
          enrollment_class: enrollment.toLowerCase(),
          session_lifetime_seconds: enrollment === 'Ephemeral' ? leaseHours * 3600 : 0,
        } })
        liveIssuedUserToken = { tokenId: issued.token_id, subject: subject.trim(), enrollment, networkName: inventory.network.name, leaseHours, token: issued.enrollment_token }
        navigate('/users/new/token')
      } catch (error) {
        setSubmitError(error instanceof Error ? error.message : 'The controller could not issue this access token.')
      } finally {
        setPending(false)
      }
      return
    }
    const id = `usr_demo_${subject.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_')}`
    const record: UserEnrollmentRecord = { id, subject: subject.trim(), enrollment: enrollment as UserEnrollmentRecord['enrollment'], network: networkName, devices: 0, lease: `${leaseHours} hours`, state: 'Active', tone: 'positive' }
    updateDemoState(current => ({ ...current, users: { ...current.users, [id]: { ...attributed('User enrollment token issued'), record } } }))
    navigate('/users/new/token', { state: { id, subject: subject.trim(), enrollment, networkName, leaseHours } })
  }

  return <div className="users-page users-form-page">
    <PageHeader title="Issue user access" description="Create a single-use enrollment token." />
    <FormLayout
      form={<FormStack onSubmit={submit}>
        <Field label="Requested node name" error={errors.subject}>
          <input value={subject} onChange={event => { setSubject(event.target.value); if (errors.subject) setErrors(current => ({ ...current, subject: '' })) }} placeholder="e.g. work-laptop" autoComplete="off" aria-invalid={Boolean(errors.subject)} />
        </Field>
        <ChoiceGroup label="Enrollment behavior" value={enrollment} onChange={setEnrollment} options={[
          { value: 'Remembered', label: 'Remembered', description: 'Persistent until revoked.' },
          { value: 'Ephemeral', label: 'Ephemeral', description: 'Expires with the lease.' },
        ]} />
        <Field label="Network"><select value={selectedNetworkName} disabled={live} onChange={event => setNetworkName(event.target.value)}>{live ? <option>{selectedNetworkName}</option> : <><option>Production</option><option>Home lab</option><option>All</option></>}</select></Field>
        <Field label="Lease duration (hours)" hint={enrollment === 'Ephemeral' ? '1–24 hours.' : undefined} error={errors.lease}><input type="number" min="1" max="24" step="1" value={lease} disabled={enrollment !== 'Ephemeral'} onChange={event => { setLease(event.target.value); if (errors.lease) setErrors(current => ({ ...current, lease: '' })) }} aria-invalid={Boolean(errors.lease)} /></Field>
        {submitError ? <Callout tone="danger">{submitError}</Callout> : null}
        <div className="button-row"><Button type="submit" variant="primary" disabled={pending || (live && !inventory?.network)}><KeyRound size={17} />{pending ? 'Issuing…' : live && (inventoryPending || !inventory?.network) ? 'Loading network…' : 'Issue user token'}</Button><Button to="/users" variant="quiet">Cancel</Button></div>
      </FormStack>}
      review={<ReviewPanel title="Access review" rows={[
        ['Subject', subject.trim() || 'Not set'], ['Enrollment', enrollment], ['Network', selectedNetworkName], ['Lease', enrollment === 'Ephemeral' ? `${lease || '—'} hours` : 'No fixed lease'], ['Redemptions', 'One'],
      ]}>{enrollment === 'Remembered' ? <Callout tone="warning">Access remains active until the enrolled node is revoked.</Callout> : null}</ReviewPanel>}
    />
  </div>
}

export function UserTokenPage() {
  const location = useLocation()
  const { live } = useControlPlane()
  const [transientIssue] = useState<IssuedUserToken | null>(() => live ? liveIssuedUserToken : null)
  const issued = live ? transientIssue : location.state as IssuedUserToken | null
  const displayedToken = issued?.token ?? userToken
  const [copyState, setCopyState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const controllerDomain = live ? new URL(controllerOrigin()).host : 'controller.example.com'
  const enrollmentCommand = userEnrollmentCommand(controllerDomain, issued?.enrollment === 'Ephemeral' ? 'Ephemeral' : 'Remembered')

  useEffect(() => {
    if (live) liveIssuedUserToken = null
  }, [live])

  async function copyToken() {
    try {
      await navigator.clipboard.writeText(displayedToken)
      setCopyState('copied')
    } catch {
      setCopyState('failed')
    }
  }

  if (live && !issued?.token) {
    return <div className="users-page users-token-page"><EmptyState icon={<Users />} title="User token unavailable" description="Live enrollment secrets are shown only once, immediately after issuance. Issue a new token to continue." action={<Button to="/users/new" variant="primary">Issue a new token</Button>} /></div>
  }

  return <div className="users-page users-token-page">
    <PageHeader title="User token issued" description="Send the single-use secret through a secure channel." />
    <div className="users-token-grid"><section className="users-panel users-token-card"><div className="users-panel-head"><h2>One-time credential</h2><Status tone="warning">Shown once</Status></div><Callout tone="warning"><strong>Copy this credential now.</strong> Laneway stores only its fingerprint and cannot reveal it again.</Callout><div className="users-token-space"><TokenBox label="User enrollment token" value={displayedToken}><Button onClick={copyToken} variant="primary">{copyState === 'copied' ? <Check size={17} /> : <Clipboard size={17} />}{copyState === 'copied' ? 'Copied' : 'Copy credential'}</Button></TokenBox></div>{copyState === 'failed' ? <Callout tone="danger">Clipboard access was blocked. Select the token text and copy it manually.</Callout> : null}</section>
    <section className="users-panel users-connect-card"><div className="users-panel-head"><h2>Connect</h2><span>Linux / macOS</span></div><p>Save the token in <code>./laneway.code</code> with mode <code>0600</code>, then run:</p><pre className="users-command" tabIndex={0}><code>{enrollmentCommand}</code></pre></section></div>
    <div className="button-row users-token-actions"><Button to={issued?.id ? `/users/${issued.id}` : '/users'} variant="primary">{issued?.id ? 'View enrollment' : 'View user access'}</Button><Button to="/users/new" variant="quiet">Issue another</Button></div>
  </div>
}

export function UserDetailPage() {
  const { live, inventory } = useControlPlane()
  const { userId } = useParams()
  const records = live ? controllerUsers(inventory?.nodes ?? [], inventory?.network?.name ?? 'Controller network') : persistedUsers()
  const user = userForId(userId, records)
  const [showRevoke, setShowRevoke] = useState(false)
  const [confirmation, setConfirmation] = useState('')
  const [revoked, setRevoked] = useState(user?.state === 'Revoked')
  if (!user) return <UserNotFound id={userId} />
  const activeUser: UserEnrollmentRecord = user
  const controllerNode = live ? inventory?.nodes.find(node => node.node_id === activeUser.id) : undefined
  const saved = live ? undefined : readDemoState().users[activeUser.id]
  const leaseExpired = live && activeUser.state === 'Expired'
  const isRevoked = live ? activeUser.state === 'Revoked' : revoked
  const identityInactive = live ? controllerNode?.revoked_at_unix_seconds !== undefined || leaseExpired : isRevoked
  const issuedAt = controllerNode ? new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(controllerNode.created_at_unix_seconds * 1000)) : 'Unavailable'
  const revokedAt = controllerNode?.revoked_at_unix_seconds ? new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(controllerNode.revoked_at_unix_seconds * 1000)) : undefined
  const leaseStatus = leaseExpired ? activeUser.lease : revokedAt ? `Revoked ${revokedAt}` : activeUser.lease
  const matches = confirmation === activeUser.subject

  function revoke(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (matches) {
      const record: UserEnrollmentRecord = { ...activeUser, state: 'Revoked', tone: 'danger', lease: 'Ended by administrator' }
      updateDemoState(current => ({ ...current, users: { ...current.users, [activeUser.id]: { ...attributed('Enrollment token revoked; attached nodes blocked'), record } } }))
      setRevoked(true)
      setShowRevoke(false)
    }
  }

  return <div className="users-page users-detail-page">
    <PageHeader title="User enrollment detail" action={<Button to="/users">Back to user access</Button>} />
    <DetailLayout identity={<IdentityBlock icon={<UserRound size={34} />} title={user.subject} state={<Status tone={isRevoked ? 'danger' : user.tone}>{live ? user.state : isRevoked ? 'Revoked' : user.state}</Status>} actions={!isRevoked && !live ? <Button variant="quiet" onClick={() => setShowRevoke(current => !current)}><Trash2 size={16} />Revoke access</Button> : undefined} metadata={[[live ? "Node ID" : "Enrollment ID", <code>{user.id}</code>], ["Type", user.enrollment], ["Network", user.network], ["Issued", live ? issuedAt : 'Aug 10, 2026'], ["Lease", live ? leaseStatus : isRevoked ? 'Ended by administrator' : user.lease]]} />}>
      {live && !identityInactive ? <Callout>User revocation is unavailable. Revoke the enrolled node instead.</Callout> : null}
      {leaseExpired ? <Callout>The lease expired. This node can no longer authenticate.</Callout> : null}
      {showRevoke && !isRevoked ? <Section title="Confirm revocation" meta="All nodes attached to this enrollment will lose access immediately.">
        <Callout tone="danger">Enrolled nodes will no longer authenticate.</Callout>
        <form className="users-confirm-form" onSubmit={revoke}><Field label={`Type ${user.subject} to confirm`} error={confirmation && !matches ? 'The subject label does not match.' : undefined}><input value={confirmation} onChange={event => setConfirmation(event.target.value)} autoComplete="off" aria-invalid={Boolean(confirmation && !matches)} /></Field><div className="button-row"><Button type="submit" variant="danger" disabled={!matches}>Revoke access</Button><Button variant="quiet" onClick={() => { setShowRevoke(false); setConfirmation('') }}>Cancel</Button></div></form>
      </Section> : null}
      {isRevoked ? live
        ? <Callout tone="danger">Enrollment revoked. This node can no longer authenticate.</Callout>
        : <Callout tone="danger">Access was revoked. The attached nodes can no longer authenticate. {saved?.result ?? 'Enrollment token revoked; attached nodes blocked'} by {saved?.actedBy ?? 'Demo operator'} · {saved?.actedAt ?? 'Aug 11, 2026 at 10:14 UTC'}.</Callout>
        : null}
      {live ? <>
        <Section title="Enrolled node">
          <div className="users-node-list"><div><EntityTitle icon={<Laptop size={17} />} subtitle={[controllerNode?.ipv4_address, controllerNode?.ipv6_address].filter(Boolean).join(' · ') || activeUser.id}>{controllerNode?.name || activeUser.subject}</EntityTitle><Status tone={activeUser.tone}>{activeUser.state}</Status></div></div>
        </Section>
        <Section title="Enrollment dates"><dl className="users-history"><div><dt><Clock3 size={16} />Issued</dt><dd>{issuedAt}</dd></div><div><dt><Clock3 size={16} />Expires</dt><dd>{leaseStatus}</dd></div></dl></Section>
      </> : <>
        <Section title="Attached nodes">
          <div className="users-node-list"><div><EntityTitle icon={<Laptop size={17} />} subtitle="100.88.0.19">operator-laptop</EntityTitle><Status tone={isRevoked ? 'danger' : 'positive'}>{isRevoked ? 'Revoked' : 'Connected'}</Status></div><div><EntityTitle icon={<Laptop size={17} />} subtitle="100.88.0.31">operator-phone</EntityTitle><Status tone={isRevoked ? 'danger' : 'muted'}>{isRevoked ? 'Revoked' : 'Offline'}</Status></div></div>
        </Section>
        <Section title="Lease history"><dl className="users-history"><div><dt><Clock3 size={16} />Issued</dt><dd>Aug 10, 2026 at 09:31 UTC</dd></div><div><dt><Clock3 size={16} />Last renewed</dt><dd>Today at 08:02 UTC</dd></div><div><dt><Clock3 size={16} />Scheduled expiry</dt><dd>{isRevoked ? 'Ended now' : 'Sep 8, 2026 at 09:31 UTC'}</dd></div></dl></Section>
      </>}
    </DetailLayout>
  </div>
}
