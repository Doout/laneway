import { useEffect, useState, type FormEvent } from 'react'
import { NavLink, useNavigate, useParams } from 'react-router-dom'
import { MonitorDot, Plus, Users } from 'lucide-react'
import { Button, Callout, DataTable, DetailLayout, EntityTitle, Field, FormStack, IdentityBlock, PageHeader, ResourceLink, SearchField, Section, Status, Toolbar, type DataColumn } from '../../components/ui'
import { useControlPlane, type ControllerAccessGrant, type ControllerAccessTeam, type ControllerAccessUser } from '../../lib/control-plane'
import { ErrorMessage, Missing, SummaryStrip, VisibilityToolbar, nodeState, routeState, time, type RecordVisibility } from './shared'

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
  const columns: DataColumn<ControllerAccessUser>[] = [
    { key: 'user', label: 'User', render: (user) => <EntityTitle icon={<Users size={16} />} subtitle={user.user_id}>{user.name}</EntityTitle> },
    { key: 'devices', label: 'Nodes', render: (user) => (inventory?.nodes ?? []).filter((node) => node.user_id === user.user_id && !nodeState(node).inactive).length },
    { key: 'teams', label: 'Teams', render: (user) => (inventory?.accessMemberships ?? []).filter((member) => member.user_id === user.user_id).length },
    { key: 'state', label: 'State', render: (user) => <Status tone={user.enabled ? 'positive' : 'muted'}>{user.enabled ? 'Enabled' : 'Disabled'}</Status> },
    { key: 'open', label: '', render: (user) => <Button to={`/users/${user.user_id}`} variant="quiet">View</Button> },
  ]
  return <><PageHeader title="People" action={networkId && hasPermission('acl.manage', networkId) ? <Button to="/users/new" variant="primary"><Plus size={16} />Create user</Button> : undefined} /><SummaryStrip label="People summary" items={[{ label: 'Enabled users', value: records.filter((user) => user.enabled).length, detail: `${records.length} total` }, { label: 'Teams', value: inventory?.accessTeams.length ?? 0 }, { label: 'Assigned nodes', value: canReadNodes ? (inventory?.nodes ?? []).filter((node) => node.user_id && !nodeState(node).inactive).length : '—', detail: canReadNodes ? undefined : 'Not authorized' }, { label: 'Access grants', value: inventory?.accessGrants.length ?? 0 }]} /><PeopleTabs /><div className="people-table"><VisibilityToolbar value={visibility} onChange={setVisibility} currentLabel="Enabled only" visible={visibleRecords.length} total={records.length}><SearchField label="Search users" placeholder="Search name or user ID" value={query} onChange={setQuery} /></VisibilityToolbar><DataTable columns={columns} rows={visibleRecords} rowKey={(user) => user.user_id} empty={<p>No users match this view.</p>} /></div></>
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
  return <><PageHeader title={user.name} action={<div className="button-row"><Button to="/users">All users</Button>{canManage ? <Button to={`/users/${user.user_id}/grants/new`}>Grant access</Button> : null}{user.enabled && hasPermission('enrollment.issue', user.network_id) ? <Button to={`/users/${user.user_id}/enroll`} variant="primary">Enroll node</Button> : null}</div>} /><ErrorMessage value={error} /><DetailLayout identity={<IdentityBlock icon={<Users size={30} />} title={user.name} state={<Status tone={user.enabled ? 'positive' : 'muted'}>{user.enabled ? 'Enabled' : 'Disabled'}</Status>} actions={canManage ? <Button variant={user.enabled ? 'danger' : 'primary'} onClick={() => void toggleUser()}>{user.enabled ? 'Disable user' : 'Enable user'}</Button> : undefined} metadata={[["User ID", <code>{user.user_id}</code>], ["Network ID", <code>{user.network_id}</code>], ["Created", time(user.created_at_unix_seconds)]]} />}>
    <Section title="Teams" meta={`${teams.length} assigned`}>{teams.length ? <div className="resource-list">{teams.map((team) => <ResourceLink key={team.team_id} to={`/teams/${team.team_id}`} icon={<Users size={18} />} title={team.name} />)}</div> : <div className="inline-empty">Not in a team.</div>}</Section>
    <Section title="Access grants" meta={`${grants.length} direct`}>{grants.length ? <div className="resource-list">{grants.map((grant) => <AccessGrantRow key={grant.grant_id} grant={grant} inventory={inventory} remove={canManage ? removeGrant : undefined} />)}</div> : <div className="inline-empty">No direct grants. Team grants may still apply.</div>}</Section>
    <Section title="Enrolled nodes" meta={`${nodes.length} current`}>{nodes.length ? <div className="resource-list">{nodes.map((node) => <ResourceLink key={node.node_id} to={`/nodes/${node.node_id}`} icon={<MonitorDot size={18} />} title={node.name || node.node_id} meta={node.enrollment_class} state={<Status tone={nodeState(node).tone}>{nodeState(node).label}</Status>} />)}</div> : <div className="inline-empty">No current nodes for this user.</div>}</Section>
  </DetailLayout></>
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
  return <><PageHeader title={`Create ${kind}`} /><FormStack onSubmit={submit}><Field label="Name"><input autoFocus value={name} onChange={(event) => setName(event.target.value)} /></Field><ErrorMessage value={error} /><div className="button-row"><Button type="submit" variant="primary">Create {kind}</Button><Button to={kind === 'user' ? '/users' : '/teams'}>Cancel</Button></div></FormStack></>
}

export function TeamsPage() {
  const { inventory, hasPermission } = useControlPlane()
  const networkId = inventory?.network?.network_id
  const records = inventory?.accessTeams ?? []
  const [query, setQuery] = useState('')
  const normalizedQuery = query.trim().toLowerCase()
  const visibleRecords = records.filter((team) => !normalizedQuery || [team.name, team.team_id].some((value) => value.toLowerCase().includes(normalizedQuery)))
  const columns: DataColumn<ControllerAccessTeam>[] = [
    { key: 'team', label: 'Team', render: (team) => <EntityTitle icon={<Users size={16} />} subtitle={team.team_id}>{team.name}</EntityTitle> },
    { key: 'members', label: 'Members', render: (team) => (inventory?.accessMemberships ?? []).filter((member) => member.team_id === team.team_id).length },
    { key: 'grants', label: 'Access grants', render: (team) => (inventory?.accessGrants ?? []).filter((grant) => grant.subject_kind === 'team' && grant.subject_id === team.team_id).length },
    { key: 'open', label: '', render: (team) => <Button to={`/teams/${team.team_id}`} variant="quiet">View</Button> },
  ]
  return <><PageHeader title="People" action={networkId && hasPermission('acl.manage', networkId) ? <Button to="/teams/new" variant="primary"><Plus size={16} />Create team</Button> : undefined} /><SummaryStrip label="People summary" items={[{ label: 'Users', value: inventory?.accessUsers.filter((user) => user.enabled).length ?? 0, detail: `${inventory?.accessUsers.length ?? 0} total`, tone: 'positive' }, { label: 'Teams', value: records.length }, { label: 'Memberships', value: inventory?.accessMemberships.length ?? 0 }, { label: 'Team grants', value: inventory?.accessGrants.filter((grant) => grant.subject_kind === 'team').length ?? 0 }]} /><PeopleTabs /><div className="people-table"><Toolbar filters={<span className="inventory-result-count" aria-live="polite">{visibleRecords.length} of {records.length} shown</span>}><SearchField label="Search teams" placeholder="Search name or team ID" value={query} onChange={setQuery} /></Toolbar><DataTable columns={columns} rows={visibleRecords} rowKey={(team) => team.team_id} empty={<p>No teams match this search.</p>} /></div></>
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
  return <><PageHeader title={team.name} action={<div className="button-row"><Button to="/teams">All teams</Button>{canManage ? <Button to={`/teams/${team.team_id}/grants/new`} variant="primary">Grant access</Button> : null}</div>} /><ErrorMessage value={error} /><DetailLayout identity={<IdentityBlock icon={<Users size={30} />} title={team.name} state={<Status tone="positive">Active</Status>} metadata={[["Team ID", <code>{team.team_id}</code>], ["Network ID", <code>{team.network_id}</code>], ["Created", time(team.created_at_unix_seconds)]]} />}>
    <Section title="Members" meta={`${members.length} users`}>{canManage && available.length ? <div className="inline-editor"><select aria-label="User to add" value={selectedUser} onChange={(event) => setSelectedUser(event.target.value)}><option value="">Choose user</option>{available.map((user) => <option key={user.user_id} value={user.user_id}>{user.name}</option>)}</select><Button disabled={!selectedUser} onClick={() => void changeMember(selectedUser, true)}>Add</Button></div> : null}{members.length ? <div className="resource-list">{members.map((user) => <div className="access-grant-row" key={user.user_id}><ResourceLink to={`/users/${user.user_id}`} icon={<Users size={18} />} title={user.name} />{canManage ? <Button variant="danger" onClick={() => void changeMember(user.user_id, false)}>Remove</Button> : null}</div>)}</div> : <div className="inline-empty">No users in this team.</div>}</Section>
    <Section title="Access grants" meta={`${grants.length} shared`}>{grants.length ? <div className="resource-list">{grants.map((grant) => <AccessGrantRow key={grant.grant_id} grant={grant} inventory={inventory} remove={canManage ? removeGrant : undefined} />)}</div> : <div className="inline-empty">No team grants.</div>}</Section>
  </DetailLayout></>
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
  return <><PageHeader title="Grant access" /><Callout tone="warning">Network access does not include exit nodes.</Callout><FormStack onSubmit={submit}><Field label="Access scope"><select value={targetKind} onChange={(event) => setTargetKind(event.target.value as typeof targetKind)}><option value="network">Entire network, excluding exits</option><option value="node">One node</option><option value="exit">One exit node</option></select></Field>{targetKind !== 'network' ? <Field label={targetKind === 'exit' ? 'Exit node' : 'Node'}><select value={nodeId} onChange={(event) => setNodeId(event.target.value)}><option value="">Choose node</option>{choices.map((node) => <option key={node.node_id} value={node.node_id}>{node.name || node.node_id}</option>)}</select></Field> : null}<ErrorMessage value={error} /><div className="button-row"><Button type="submit" variant="primary">Grant access</Button><Button to={subjectKind === 'user' ? `/users/${subjectId}` : `/teams/${subjectId}`}>Cancel</Button></div></FormStack></>
}
