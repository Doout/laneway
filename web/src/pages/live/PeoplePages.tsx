import { useEffect, useState, type ReactNode, type FormEvent } from 'react'
import { Link, NavLink, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, ChevronRight, KeyRound, MonitorDot, Plus, UserRound, Users } from 'lucide-react'
import { Button, Callout, Field, FormStack, PageHeader, ResourceLink, SearchField, Section, Status, Toolbar } from '../../components/ui'
import { useControlPlane, type ControllerAccessGrant, type ControllerAccessTeam, type ControllerAccessUser } from '../../lib/control-plane'
import { ErrorMessage, Missing, SummaryStrip, VisibilityToolbar, nodeState, routeState, time, type RecordVisibility } from './shared'
import './people.css'

function countLabel(count: number, noun: string) {
  return `${count} ${noun}${count === 1 ? '' : 's'}`
}

function DirectoryRow({ to, name, id, team, children }: { to: string; name: string; id: string; team?: boolean; children: ReactNode }) {
  return <li><Link className="people-entry" to={to}>
    <span className="people-entry__icon" aria-hidden="true">{team ? <Users size={18} /> : <UserRound size={18} />}</span>
    <span className="people-entry__name"><strong>{name}</strong><small>{id}</small></span>
    <span className="people-entry__facts">{children}</span><ChevronRight size={15} aria-hidden="true" />
  </Link></li>
}

function PeopleBack({ to, children }: { to: string; children: ReactNode }) {
  return <Link className="people-back" to={to}><ArrowLeft size={14} aria-hidden="true" />{children}</Link>
}

function PeopleTabs() {
  const { inventory } = useControlPlane()
  return <nav className="people-tabs" aria-label="People views">
    <NavLink to="/users" end><span>Users</span><span aria-hidden="true">{inventory?.accessUsers.length ?? 0}</span></NavLink>
    <NavLink to="/teams" end><span>Teams</span><span aria-hidden="true">{inventory?.accessTeams.length ?? 0}</span></NavLink>
  </nav>
}

export function UsersPage() {
  const { inventory, hasPermission } = useControlPlane()
  const records = inventory?.accessUsers ?? []
  const networkId = inventory?.network?.network_id
  const canReadNodes = Boolean(networkId && hasPermission('node.read', networkId))
  const [visibility, setVisibility] = useState<RecordVisibility>('current')
  const [query, setQuery] = useState('')
  const normalizedQuery = query.trim().toLowerCase()
  const visibleRecords = records.filter((user) => (visibility === 'all' || user.enabled) && (!normalizedQuery || [user.name, user.user_id].some((value) => value.toLowerCase().includes(normalizedQuery))))
  return <div className="people-directory">
    <PageHeader title="People" action={networkId && hasPermission('acl.manage', networkId) ? <Button to="/users/new" variant="primary"><Plus size={16} />Create user</Button> : undefined} />
    <PeopleTabs />
    <VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Enabled only" visible={visibleRecords.length} total={records.length}>
      <SearchField label="Search users" placeholder="Search name or user ID" value={query} onChange={setQuery} />
    </VisibilityToolbar>
    {visibleRecords.length ? <ul className="people-entries" aria-label="Users">{visibleRecords.map(user => <DirectoryRow key={user.user_id} to={`/users/${user.user_id}`} name={user.name} id={user.user_id}>
      <span>{canReadNodes ? countLabel((inventory?.nodes ?? []).filter(node => node.user_id === user.user_id && !nodeState(node).inactive).length, 'node') : 'Node count unavailable'}</span>
      <span>{countLabel((inventory?.accessMemberships ?? []).filter(member => member.user_id === user.user_id).length, 'team')}</span>
      <Status tone={user.enabled ? 'positive' : 'muted'}>{user.enabled ? 'Enabled' : 'Disabled'}</Status>
    </DirectoryRow>)}</ul> : <p className="inline-empty">No users match this view.</p>}
    <details className="people-disclosure"><summary>Directory totals</summary><SummaryStrip label="People summary" items={[{ label: 'Enabled users', value: records.filter(user => user.enabled).length, detail: `${records.length} total` }, { label: 'Teams', value: inventory?.accessTeams.length ?? 0 }, { label: 'Assigned nodes', value: canReadNodes ? (inventory?.nodes ?? []).filter(node => node.user_id && !nodeState(node).inactive).length : '—', detail: canReadNodes ? undefined : 'Not authorized' }, { label: 'Access grants', value: inventory?.accessGrants.length ?? 0 }]} /></details>
  </div>
}

export function UserDetailPage() {
  const { userId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const user = inventory?.accessUsers.find((candidate) => candidate.user_id === userId)
  const [error, setError] = useState('')
  if (!user) return <Missing title="User not found" back="/users" />
  const activeUser = user
  const nodes = (inventory?.nodes ?? []).filter((node) => node.user_id === user.user_id && !nodeState(node).inactive)
  const teamIds = new Set((inventory?.accessMemberships ?? []).filter((member) => member.user_id === user.user_id).map((member) => member.team_id))
  const teams = (inventory?.accessTeams ?? []).filter((team) => teamIds.has(team.team_id))
  const grants = (inventory?.accessGrants ?? []).filter((grant) => grant.subject_kind === 'user' && grant.subject_id === user.user_id)
  const canManage = hasPermission('acl.manage', user.network_id)
  async function toggleUser() {
    try { await request(`/v1/admin/users/${activeUser.user_id}`, { method: 'PATCH', body: { enabled: !activeUser.enabled } }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'User update failed.') }
  }
  async function removeGrant(grantId: string) {
    try { await request(`/v1/admin/access-grants/${grantId}`, { method: 'DELETE' }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Grant removal failed.') }
  }
  return <div className="people-record">
    <PeopleBack to="/users">All users</PeopleBack>
    <PageHeader title={user.name} action={<div className="button-row">{canManage ? <Button to={`/users/${user.user_id}/grants/new`}>Grant access</Button> : null}{user.enabled && hasPermission('enrollment.issue', user.network_id) ? <Button to={`/users/${user.user_id}/enroll`} variant="primary">Enroll node</Button> : null}</div>} />
    <div className="people-byline"><Status tone={user.enabled ? 'positive' : 'muted'}>{user.enabled ? 'Enabled' : 'Disabled'}</Status><span>{inventory?.network?.name ?? user.network_id}</span></div>
    <ErrorMessage value={error} />
    <div className="people-relationships">
    <Section title="Teams" meta={`${teams.length} assigned`}>{teams.length ? <div className="resource-list">{teams.map((team) => <ResourceLink key={team.team_id} to={`/teams/${team.team_id}`} icon={<Users size={18} />} title={team.name} />)}</div> : <div className="inline-empty">Not in a team.</div>}</Section>
    <Section title="Access grants" meta={`${grants.length} direct`}>{grants.length ? <div className="resource-list">{grants.map((grant) => <AccessGrantRow key={grant.grant_id} grant={grant} inventory={inventory} remove={canManage ? removeGrant : undefined} />)}</div> : <div className="inline-empty">No direct grants. Team grants may still apply.</div>}</Section>
    <Section title="Enrolled nodes" meta={`${nodes.length} current`}>{nodes.length ? <div className="resource-list">{nodes.map((node) => <ResourceLink key={node.node_id} to={`/nodes/${node.node_id}`} icon={<MonitorDot size={18} />} title={node.name || node.node_id} meta={node.enrollment_class} state={<Status tone={nodeState(node).tone}>{nodeState(node).label}</Status>} />)}</div> : <div className="inline-empty">No current nodes for this user.</div>}</Section>
    </div>
    <details className="people-disclosure"><summary>User details</summary>
      <dl className="people-properties"><div><dt>User ID</dt><dd><code>{user.user_id}</code></dd></div><div><dt>Network ID</dt><dd><code>{user.network_id}</code></dd></div><div><dt>Created</dt><dd>{time(user.created_at_unix_seconds)}</dd></div></dl>
      {canManage && <Button variant={user.enabled ? 'danger' : 'primary'} onClick={() => void toggleUser()}>{user.enabled ? 'Disable user' : 'Enable user'}</Button>}
    </details>
  </div>
}

function AccessGrantRow({ grant, inventory, remove }: { grant: ControllerAccessGrant; inventory: ReturnType<typeof useControlPlane>['inventory']; remove?: (id: string) => Promise<void> }) {
  const node = grant.node_id ? inventory?.nodes.find((candidate) => candidate.node_id === grant.node_id) : undefined
  const title = grant.target_kind === 'network' ? `Network: ${inventory?.network?.name ?? grant.network_id}` : grant.target_kind === 'exit' ? `Exit: ${node?.name ?? grant.node_id}` : `Node: ${node?.name ?? grant.node_id}`
  return <div className="access-grant-row"><span><strong>{title}</strong><small>{grant.target_kind === 'network' ? 'Exit access is not included' : grant.target_kind === 'exit' ? 'Default route only' : 'This node only'}</small></span>{remove ? <Button variant="danger" onClick={() => void remove(grant.grant_id)}>Remove</Button> : null}</div>
}

export function CreateUserPage() { return <CreateAccessSubject kind="user" /> }
export function CreateTeamPage() { return <CreateAccessSubject kind="team" /> }

function CreateAccessSubject({ kind }: { kind: 'user' | 'team' }) {
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!inventory?.network) return
    try {
      const created = await request<ControllerAccessUser | ControllerAccessTeam>(`/v1/admin/networks/${inventory.network.network_id}/${kind === 'user' ? 'users' : 'teams'}`, { method: 'POST', body: { name: name.trim() } })
      await refresh()
      navigate(kind === 'user' ? `/users/${(created as ControllerAccessUser).user_id}` : `/teams/${(created as ControllerAccessTeam).team_id}`)
    } catch (cause) { setError(cause instanceof Error ? cause.message : `${kind === 'user' ? 'User' : 'Team'} creation failed.`) }
  }
  const directory = kind === 'user' ? '/users' : '/teams'
  return <div className="people-editor">
    <PeopleBack to={directory}>All {kind}s</PeopleBack><PageHeader title={`Create ${kind}`} />
    <FormStack onSubmit={submit}>
      <div className="people-editor__context">{kind === 'user' ? <UserRound size={18} /> : <Users size={18} />}<span>Network<strong>{inventory?.network?.name ?? 'No network selected'}</strong></span></div>
      <Field label="Name"><input autoFocus value={name} onChange={event => setName(event.target.value)} /></Field>
      <ErrorMessage value={error} />
      <div className="button-row"><Button type="submit" variant="primary">Create {kind}</Button><Button to={directory} variant="quiet">Cancel</Button></div>
    </FormStack>
  </div>
}

export function TeamsPage() {
  const { inventory, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const records = inventory?.accessTeams ?? []
  const [query, setQuery] = useState('')
  const normalizedQuery = query.trim().toLowerCase()
  const visibleRecords = records.filter((team) => !normalizedQuery || [team.name, team.team_id].some((value) => value.toLowerCase().includes(normalizedQuery)))
  return <div className="people-directory">
    <PageHeader title="People" action={networkId && hasPermission('acl.manage', networkId) ? <Button to="/teams/new" variant="primary"><Plus size={16} />Create team</Button> : undefined} />
    <PeopleTabs />
    <Toolbar filters={<span className="inventory-result-count" aria-live="polite">{visibleRecords.length} of {records.length} shown</span>}>
      <SearchField label="Search teams" placeholder="Search name or team ID" value={query} onChange={setQuery} />
    </Toolbar>
    {visibleRecords.length ? <ul className="people-entries" aria-label="Teams">{visibleRecords.map(team => <DirectoryRow team key={team.team_id} to={`/teams/${team.team_id}`} name={team.name} id={team.team_id}>
      <span>{countLabel((inventory?.accessMemberships ?? []).filter(member => member.team_id === team.team_id).length, 'member')}</span>
      <span>{countLabel((inventory?.accessGrants ?? []).filter(grant => grant.subject_kind === 'team' && grant.subject_id === team.team_id).length, 'grant')}</span>
    </DirectoryRow>)}</ul> : <p className="inline-empty">No teams match this search.</p>}
    <details className="people-disclosure"><summary>Directory totals</summary><SummaryStrip label="People summary" items={[{ label: 'Users', value: inventory?.accessUsers.filter(user => user.enabled).length ?? 0, detail: `${inventory?.accessUsers.length ?? 0} total` }, { label: 'Teams', value: records.length }, { label: 'Memberships', value: inventory?.accessMemberships.length ?? 0 }, { label: 'Team grants', value: inventory?.accessGrants.filter(grant => grant.subject_kind === 'team').length ?? 0 }]} /></details>
  </div>
}

export function TeamDetailPage() {
  const { teamId } = useParams()
  const { inventory, hasPermission, request, refresh } = useControlPlane()
  const team = inventory?.accessTeams.find((candidate) => candidate.team_id === teamId)
  const [selectedUser, setSelectedUser] = useState('')
  const [error, setError] = useState('')
  if (!team) return <Missing title="Team not found" back="/teams" />
  const activeTeam = team
  const memberships = (inventory?.accessMemberships ?? []).filter((member) => member.team_id === team.team_id)
  const memberIds = new Set(memberships.map((member) => member.user_id))
  const members = (inventory?.accessUsers ?? []).filter((user) => memberIds.has(user.user_id))
  const available = (inventory?.accessUsers ?? []).filter((user) => user.enabled && !memberIds.has(user.user_id))
  const grants = (inventory?.accessGrants ?? []).filter((grant) => grant.subject_kind === 'team' && grant.subject_id === team.team_id)
  const canManage = hasPermission('acl.manage', team.network_id)
  async function changeMember(userId: string, present: boolean) {
    try { await request(`/v1/admin/teams/${activeTeam.team_id}/members/${userId}`, { method: present ? 'PUT' : 'DELETE' }); setSelectedUser(''); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Team membership update failed.') }
  }
  async function removeGrant(grantId: string) {
    try { await request(`/v1/admin/access-grants/${grantId}`, { method: 'DELETE' }); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Grant removal failed.') }
  }
  return <div className="people-record">
    <PeopleBack to="/teams">All teams</PeopleBack>
    <PageHeader title={team.name} action={<div className="button-row">{canManage ? <Button to={`/teams/${team.team_id}/grants/new`} variant="primary">Grant access</Button> : null}</div>} />
    <div className="people-byline"><Status>Active</Status><span>{inventory?.network?.name ?? team.network_id}</span></div>
    <ErrorMessage value={error} />
    <div className="people-relationships">
    <Section title="Members" meta={countLabel(members.length, 'user')}>{canManage && available.length ? <div className="inline-editor"><select aria-label="User to add" value={selectedUser} onChange={(event) => setSelectedUser(event.target.value)}><option value="">Choose user</option>{available.map((user) => <option key={user.user_id} value={user.user_id}>{user.name}</option>)}</select><Button disabled={!selectedUser} onClick={() => void changeMember(selectedUser, true)}>Add</Button></div> : null}{members.length ? <div className="resource-list">{members.map((user) => <div className="access-grant-row" key={user.user_id}><ResourceLink to={`/users/${user.user_id}`} icon={<Users size={18} />} title={user.name} />{canManage ? <Button variant="danger" onClick={() => void changeMember(user.user_id, false)}>Remove</Button> : null}</div>)}</div> : <div className="inline-empty">No users in this team.</div>}</Section>
    <Section title="Access grants" meta={`${grants.length} shared`}>{grants.length ? <div className="resource-list">{grants.map((grant) => <AccessGrantRow key={grant.grant_id} grant={grant} inventory={inventory} remove={canManage ? removeGrant : undefined} />)}</div> : <div className="inline-empty">No team grants.</div>}</Section>
    </div>
    <details className="people-disclosure"><summary>Team details</summary>
      <dl className="people-properties"><div><dt>Team ID</dt><dd><code>{team.team_id}</code></dd></div><div><dt>Network ID</dt><dd><code>{team.network_id}</code></dd></div><div><dt>Created</dt><dd>{time(team.created_at_unix_seconds)}</dd></div></dl>
    </details>
  </div>
}

export function CreateGrantPage({ subjectKind }: { subjectKind: 'user' | 'team' }) {
  const { userId, teamId } = useParams()
  const subjectId = subjectKind === 'user' ? userId : teamId
  const { inventory, request, refresh } = useControlPlane()
  const navigate = useNavigate()
  const [targetKind, setTargetKind] = useState<'network' | 'node' | 'exit'>('network')
  const [nodeId, setNodeId] = useState('')
  const [error, setError] = useState('')
  const activeNodes = (inventory?.nodes ?? []).filter((node) => !nodeState(node).inactive)
  const exitIds = new Set((inventory?.routes ?? []).filter((route) => route.kind === 'exit' && route.state === 'approved' && routeState(route).actionable).map((route) => route.node_id))
  const choices = targetKind === 'exit' ? activeNodes.filter((node) => exitIds.has(node.node_id)) : activeNodes
  useEffect(() => { if (targetKind === 'network') setNodeId(''); else if (!choices.some((node) => node.node_id === nodeId)) setNodeId(choices[0]?.node_id ?? '') }, [choices, nodeId, targetKind])
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!inventory?.network || !subjectId || (targetKind !== 'network' && !nodeId)) return setError('Choose a valid access target.')
    try { await request(`/v1/admin/networks/${inventory.network.network_id}/access-grants`, { method: 'POST', body: { subject_kind: subjectKind, subject_id: subjectId, target_kind: targetKind, ...(targetKind === 'network' ? {} : { node_id: nodeId }) } }); await refresh(); navigate(subjectKind === 'user' ? `/users/${subjectId}` : `/teams/${subjectId}`) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Access grant failed.') }
  }
  const subject = subjectKind === 'user' ? inventory?.accessUsers.find(user => user.user_id === subjectId) : inventory?.accessTeams.find(team => team.team_id === subjectId)
  const back = subjectKind === 'user' ? `/users/${subjectId}` : `/teams/${subjectId}`
  return <div className="people-editor">
    <PeopleBack to={back}>{subject?.name ?? (subjectKind === 'user' ? 'User details' : 'Team details')}</PeopleBack>
    <PageHeader title="Grant access" />
    <FormStack onSubmit={submit}>
      <div className="people-editor__context"><KeyRound size={18} /><span>{subjectKind === 'user' ? 'User' : 'Team'}<strong>{subject?.name ?? subjectId}</strong></span></div>
      <Field label="Access scope"><select value={targetKind} onChange={event => setTargetKind(event.target.value as typeof targetKind)}><option value="network">Entire network, excluding exits</option><option value="node">One node</option><option value="exit">One exit node</option></select></Field>
      {targetKind === 'network' ? <Callout>Network access does not include exit nodes.</Callout> : <Field label={targetKind === 'exit' ? 'Exit node' : 'Node'}><select value={nodeId} onChange={event => setNodeId(event.target.value)}><option value="">Choose node</option>{choices.map(node => <option key={node.node_id} value={node.node_id}>{node.name || node.node_id}</option>)}</select></Field>}
      <ErrorMessage value={error} />
      <div className="button-row"><Button type="submit" variant="primary">Grant access</Button><Button to={back} variant="quiet">Cancel</Button></div>
    </FormStack>
  </div>
}
