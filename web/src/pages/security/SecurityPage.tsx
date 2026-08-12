import { useMemo, useState, type FormEvent } from 'react'
import { ArrowRight, Ban, Check, Copy, FileKey2, KeyRound, RotateCw, TicketCheck, X } from 'lucide-react'
import { Button, Callout, Field, PageHeader, Status, TokenBox } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'
import { attributed, readDemoState, updateDemoState, type AttributedChange } from '../../lib/persisted-demo-state'
import './security.css'

interface CertificateRecord {
  id: string
  name: string
  purpose: string
  expires: string
  state: string
  tone: 'positive' | 'warning' | 'danger' | 'muted'
  networkId?: string
  serial?: string
  nodeId?: string
}

interface TokenRecord {
  id: string
  label: string
  type: string
  scope: string
  lastUsed: string
  expires: string
  state: string
  tone: 'positive' | 'warning' | 'danger' | 'muted'
}

const initialCertificates: CertificateRecord[] = [
  { id: 'crt_controller', name: 'controller-ca', purpose: 'Controller trust', expires: 'May 18, 2027', state: 'Valid', tone: 'positive' },
  { id: 'crt_fra_relay', name: 'fra-relay-02', purpose: 'Relay identity', expires: 'Nov 10, 2026', state: 'Valid', tone: 'positive' },
  { id: 'crt_legacy', name: 'legacy-oracle', purpose: 'Node identity', expires: 'Oct 12, 2026', state: 'Rotate soon', tone: 'warning' },
]

const initialTokens: TokenRecord[] = [
  { id: 'tok_edge', label: 'chicago-edge-02', type: 'Setup key', scope: 'Node · Production', lastUsed: 'Unused', expires: '26 min', state: 'Unredeemed', tone: 'warning' },
  { id: 'tok_oncall', label: 'Platform on-call', type: 'User token', scope: 'User · Home', lastUsed: '2 hours ago', expires: 'Redeemed', state: 'Redeemed', tone: 'positive' },
  { id: 'tok_lab', label: 'lab-connector', type: 'Setup key', scope: 'Node · Lab', lastUsed: 'Never', expires: 'Expired', state: 'Expired', tone: 'muted' },
]

type SecurityAction =
  | { kind: 'issue' }
  | { kind: 'revokeToken'; id: string; label: string }
  | { kind: 'rotate'; id: string; label: string }
  | { kind: 'revokeCertificate'; id: string; label: string; networkId: string; serial: string }

function initialSecurityResult() {
  const state = readDemoState()
  return [...Object.values(state.tokens), ...Object.values(state.certificates)].at(-1)
}

function dateLabel(seconds: number) {
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(seconds * 1000))
}

export function SecurityPage() {
  const { live, inventory, inventoryPending, inventoryError, request, refresh } = useControlPlane()
  const [demoTokens, setDemoTokens] = useState(() => {
    const changes = readDemoState().tokens
    return initialTokens.map((token) => changes[token.id] ? { ...token, state: changes[token.id].state, tone: 'danger' as const } : token)
  })
  const [demoCertificates, setDemoCertificates] = useState(() => {
    const changes = readDemoState().certificates
    return initialCertificates.map((certificate) => changes[certificate.id] ? { ...certificate, ...changes[certificate.id], tone: 'warning' as const } : certificate)
  })
  const liveCertificates = useMemo<CertificateRecord[]>(() => (inventory?.certificates ?? []).map((certificate) => {
    const nodeName = inventory?.nodes.find((node) => node.node_id === certificate.node_id)?.name ?? certificate.node_id
    const remainingMs = certificate.not_after_unix_seconds * 1000 - Date.now()
    const expired = remainingMs <= 0
    const expiresSoon = !expired && remainingMs < 30 * 24 * 60 * 60 * 1000
    return {
      id: certificate.certificate_id,
      name: nodeName,
      purpose: 'Node identity',
      expires: dateLabel(certificate.not_after_unix_seconds),
      state: certificate.revoked_at_unix_seconds ? 'Revoked' : expired ? 'Expired' : expiresSoon ? 'Expires soon' : 'Not revoked',
      tone: certificate.revoked_at_unix_seconds || expired ? 'danger' : expiresSoon ? 'warning' : 'positive',
      networkId: certificate.network_id,
      serial: certificate.serial,
      nodeId: certificate.node_id,
    }
  }), [inventory])
  const tokens = live ? [] : demoTokens
  const certificates = live ? liveCertificates : demoCertificates
  const [view, setView] = useState<'tokens' | 'certificates'>(live ? 'certificates' : 'tokens')
  const [selectedId, setSelectedId] = useState(() => live ? '' : initialTokens[0].id)
  const [issuedToken, setIssuedToken] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [copyError, setCopyError] = useState('')
  const [pendingAction, setPendingAction] = useState<SecurityAction | null>(null)
  const [confirmation, setConfirmation] = useState('')
  const [actionError, setActionError] = useState('')
  const [reason, setReason] = useState('')
  const [actionPending, setActionPending] = useState(false)
  const [result, setResult] = useState<AttributedChange | undefined>(() => live ? undefined : initialSecurityResult())

  const activeToken = tokens.find((token) => token.id === selectedId) ?? tokens[0]
  const activeCertificate = certificates.find((certificate) => certificate.id === selectedId) ?? certificates[0]
  const activeRecord = view === 'tokens' ? activeToken : activeCertificate
  const expected = pendingAction ? pendingAction.kind === 'issue' ? 'ISSUE TOKEN' : pendingAction.label : ''

  function selectView(next: 'tokens' | 'certificates') {
    setView(next)
    setSelectedId(next === 'tokens' ? tokens[0]?.id ?? '' : certificates[0]?.id ?? '')
  }

  function issueToken() {
    setIssuedToken('lwy_enroll_7Q8M-4K2D-9P3X-A1NC')
    setCopied(false)
    setCopyError('')
  }

  async function copyToken() {
    if (!issuedToken) return
    try { await navigator.clipboard.writeText(issuedToken); setCopied(true); setCopyError('') } catch { setCopied(false); setCopyError('Clipboard access was blocked. Select and copy the token manually.') }
  }

  function revokeToken(id: string) {
    setDemoTokens((rows) => rows.map((row) => row.id === id ? { ...row, state: 'Revoked', tone: 'danger' as const } : row))
    const change = { ...attributed('Enrollment token revoked'), state: 'Revoked' as const }
    updateDemoState((current) => ({ ...current, tokens: { ...current.tokens, [id]: change } }))
    setResult(change)
  }

  function rotateCertificate(id: string) {
    setDemoCertificates((rows) => rows.map((row) => row.id === id ? { ...row, expires: 'Aug 11, 2027', state: 'Rotation queued', tone: 'warning' as const } : row))
    const change = { ...attributed('Certificate rotation queued'), expires: 'Aug 11, 2027', state: 'Rotation queued' as const }
    updateDemoState((current) => ({ ...current, certificates: { ...current.certificates, [id]: change } }))
    setResult(change)
  }

  function beginAction(action: SecurityAction) {
    setPendingAction(action)
    setConfirmation('')
    setActionError('')
    setReason('')
  }

  function cancelAction() {
    setPendingAction(null)
    setConfirmation('')
    setActionError('')
    setActionPending(false)
    setReason('')
  }

  async function confirmAction(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!pendingAction || confirmation !== expected) return
    if (pendingAction.kind === 'revokeCertificate' && !reason.trim()) { setActionError('Enter a revocation reason that will be written to the audit log.'); return }
    setActionPending(true)
    setActionError('')
    try {
      if (pendingAction.kind === 'issue') { issueToken(); setResult(attributed('One-time enrollment token issued')) }
      if (pendingAction.kind === 'revokeToken') revokeToken(pendingAction.id)
      if (pendingAction.kind === 'rotate') rotateCertificate(pendingAction.id)
      if (pendingAction.kind === 'revokeCertificate') {
        await request(`/v1/admin/networks/${pendingAction.networkId}/certificates/${pendingAction.serial}/revoke`, { method: 'POST', body: { reason: reason.trim() } })
        await refresh()
        setResult({ result: 'Certificate revoked', actedBy: '', actedAt: '' })
      }
      cancelAction()
    } catch (error) {
      setActionPending(false)
      setActionError(error instanceof Error ? error.message : 'The security change could not be completed. Try again.')
    }
  }

  const nonRevokedCertificates = certificates.filter((certificate) => certificate.state !== 'Revoked').length
  const expiringCertificates = certificates.filter((certificate) => certificate.tone === 'warning').length
  const activeCredentials = tokens.filter((token) => token.state === 'Unredeemed').length

  return (
    <>
      <PageHeader title="Security" action={<Button disabled={live} onClick={() => beginAction({ kind: 'issue' })} title={live ? 'Unavailable from the controller API.' : undefined} variant="primary"><KeyRound aria-hidden="true" size={17} /> Issue credential</Button>} />

      {result ? <div className="security-result" role="status"><Check aria-hidden="true" size={16} />{result.result}{live ? '.' : ` by ${result.actedBy} · ${result.actedAt}.`}</div> : null}
      {inventoryPending ? <p className="security-loading" role="status">Refreshing certificate inventory…</p> : null}
      {inventoryError ? <p className="security-error" role="alert">Controller certificate inventory is unavailable: {inventoryError}</p> : null}

      {pendingAction ? <section className="security-confirm" aria-labelledby="security-confirm-title"><div><h2 id="security-confirm-title">Confirm security change</h2></div><Callout tone={pendingAction.kind === 'issue' ? 'warning' : 'danger'}><strong>Impact:</strong> {pendingAction.kind === 'issue' ? 'a new bearer secret can enroll one identity until it expires or is redeemed.' : pendingAction.kind === 'revokeToken' ? `${pendingAction.label} becomes unusable immediately and cannot enroll its intended identity.` : pendingAction.kind === 'rotate' ? `${pendingAction.label} begins trust-material rotation; existing trust remains until replacement distribution is confirmed.` : `${pendingAction.label} is rejected by the controller immediately. Sessions using this certificate may disconnect, and this serial cannot be restored.`}</Callout><form className="security-confirm__form" onSubmit={confirmAction}>{pendingAction.kind === 'revokeCertificate' ? <Field label="Audit reason"><input maxLength={180} onChange={(event) => setReason(event.target.value)} value={reason} /></Field> : null}<Field label={`Type ${expected} to confirm`} error={actionError || undefined}><input autoComplete="off" onChange={(event) => { setConfirmation(event.target.value); setActionError('') }} value={confirmation} /></Field><div className="button-row"><Button disabled={actionPending || confirmation !== expected} type="submit" variant={pendingAction.kind === 'issue' ? 'primary' : 'danger'}>{actionPending ? 'Applying…' : pendingAction.kind === 'issue' ? 'Issue token' : pendingAction.kind === 'revokeToken' ? 'Revoke token' : pendingAction.kind === 'rotate' ? 'Queue rotation' : 'Revoke certificate'}</Button><Button disabled={actionPending} onClick={cancelAction} variant="quiet">Cancel</Button></div></form></section> : null}

      {issuedToken ? <div className="security-issued" role="status"><div className="security-issued__header"><div><span>One-time secret</span><h2>Enrollment token issued</h2></div><Button aria-label="Dismiss issued token" onClick={() => setIssuedToken(null)} variant="quiet"><X aria-hidden="true" size={16} /></Button></div><TokenBox label="Single-use enrollment token" value={issuedToken}><Button onClick={copyToken} variant="secondary">{copied ? <Check aria-hidden="true" size={16} /> : <Copy aria-hidden="true" size={16} />}{copied ? 'Copied' : 'Copy token'}</Button></TokenBox>{copyError ? <p className="security-error" role="alert">{copyError}</p> : null}<Callout tone="warning">Shown once. Store or send it securely; it cannot be recovered.</Callout></div> : null}

      <div className="security-health-strip" aria-label="Security inventory summary"><div>{live ? <FileKey2 aria-hidden="true" size={16} /> : <TicketCheck aria-hidden="true" size={16} />}<span><strong>{live ? certificates.length : activeCredentials}</strong><small>{live ? 'Certificate records' : 'Active credentials'}</small></span></div><div><TicketCheck aria-hidden="true" size={16} /><span><strong>{nonRevokedCertificates}/{certificates.length}</strong><small>{live ? 'Not revoked' : 'Certificates valid'}</small></span></div><div><RotateCw aria-hidden="true" size={16} /><span><strong>{expiringCertificates}</strong><small>{live ? 'Expire within 30 days' : 'Rotation suggested'}</small></span></div></div>

      <div className="security-workspace">
        <section className="security-inventory" aria-labelledby="security-inventory-title">
          <div className="security-panel-head"><div><h2 id="security-inventory-title">Credential inventory</h2></div><div className="security-tabs" role="tablist"><button aria-selected={view === 'tokens'} disabled={live} onClick={() => selectView('tokens')} role="tab" type="button">Tokens</button><button aria-selected={view === 'certificates'} onClick={() => selectView('certificates')} role="tab" type="button">Certificates</button></div></div>
          <div className="security-list-head"><span>Credential</span><span>Scope</span><span>{view === 'tokens' ? 'Expires' : 'Valid until'}</span><span>State</span></div>
          {view === 'tokens' ? tokens.map((token) => <button className={`security-list-row${activeToken?.id === token.id ? ' is-selected' : ''}`} key={token.id} onClick={() => setSelectedId(token.id)} type="button"><span className="security-entity"><KeyRound aria-hidden="true" size={16} /><span><strong>{token.label}</strong><small><code>{token.id}</code></small></span></span><span>{token.scope}</span><span>{token.expires}</span><Status tone={token.tone}>{token.state}</Status></button>) : certificates.map((certificate) => <button className={`security-list-row${activeCertificate?.id === certificate.id ? ' is-selected' : ''}`} key={certificate.id} onClick={() => setSelectedId(certificate.id)} type="button"><span className="security-entity"><FileKey2 aria-hidden="true" size={16} /><span><strong>{certificate.name}</strong><small><code>{certificate.id}</code></small></span></span><span>{certificate.purpose}</span><span>{certificate.expires}</span><Status tone={certificate.tone}>{certificate.state}</Status></button>)}
          {!activeRecord ? <div className="security-empty"><h2>{live ? 'No certificate records' : 'No credentials'}</h2>{!live ? <p>Issue a credential or enroll a node.</p> : null}</div> : null}
        </section>

        <aside className="security-inspector" aria-label="Selected credential detail">
          {view === 'tokens' && activeToken ? <><div className="security-inspector-head"><span className="security-inspector-icon"><KeyRound aria-hidden="true" size={20} /></span><div><h2>{activeToken.label}</h2><p>{activeToken.type}</p></div><Status tone={activeToken.tone}>{activeToken.state}</Status></div><div className="security-scope-path"><span>Token</span><ArrowRight aria-hidden="true" size={14} /><span>{activeToken.scope}</span></div><dl><div><dt>Token ID</dt><dd><code>{activeToken.id}</code></dd></div><div><dt>Type</dt><dd>{activeToken.type}</dd></div><div><dt>Scope</dt><dd>{activeToken.scope}</dd></div><div><dt>Last used</dt><dd>{activeToken.lastUsed}</dd></div><div><dt>Expires</dt><dd>{activeToken.expires}</dd></div><div><dt>Uses remaining</dt><dd>{activeToken.state === 'Unredeemed' ? '1 of 1' : '0 of 1'}</dd></div></dl><div className="security-impact"><h3>Revocation impact</h3><p>Revoking prevents future enrollment with this token. It does not disconnect identities already enrolled.</p></div>{activeToken.state === 'Unredeemed' ? <Button onClick={() => beginAction({ kind: 'revokeToken', id: activeToken.id, label: activeToken.label })} variant="danger"><Ban aria-hidden="true" size={16} /> Revoke token</Button> : null}</> : null}
          {view === 'certificates' && activeCertificate ? <><div className="security-inspector-head"><span className="security-inspector-icon"><FileKey2 aria-hidden="true" size={20} /></span><div><h2>{activeCertificate.name}</h2><p>{activeCertificate.purpose}</p></div><Status tone={activeCertificate.tone}>{activeCertificate.state}</Status></div><dl><div><dt>Certificate ID</dt><dd><code>{activeCertificate.id}</code></dd></div>{activeCertificate.serial ? <div><dt>Serial</dt><dd><code>{activeCertificate.serial}</code></dd></div> : null}{activeCertificate.nodeId ? <div><dt>Node ID</dt><dd><code>{activeCertificate.nodeId}</code></dd></div> : null}<div><dt>Purpose</dt><dd>{activeCertificate.purpose}</dd></div><div><dt>Valid until</dt><dd>{activeCertificate.expires}</dd></div><div><dt>State</dt><dd>{activeCertificate.state}</dd></div></dl><div className={`security-impact${activeCertificate.state === 'Revoked' ? ' is-danger' : ''}`}><h3>{live ? activeCertificate.state === 'Expired' ? 'Expired certificate' : 'Revocation impact' : 'Rotation impact'}</h3><p>{live ? activeCertificate.state === 'Expired' ? 'Revocation is unavailable after expiry.' : 'Revocation is immediate and cannot be reversed. Sessions using this certificate may disconnect.' : 'The existing certificate remains trusted until replacement distribution is confirmed.'}</p></div>{activeCertificate.state !== 'Revoked' && activeCertificate.state !== 'Expired' ? live && activeCertificate.networkId && activeCertificate.serial ? <Button onClick={() => beginAction({ kind: 'revokeCertificate', id: activeCertificate.id, label: activeCertificate.name, networkId: activeCertificate.networkId!, serial: activeCertificate.serial! })} variant="danger"><Ban aria-hidden="true" size={16} /> Revoke certificate</Button> : <Button disabled={live} onClick={() => beginAction({ kind: 'rotate', id: activeCertificate.id, label: activeCertificate.name })} title={live ? 'Unavailable from the controller API.' : undefined} variant="secondary"><RotateCw aria-hidden="true" size={16} /> Rotate certificate</Button> : null}</> : null}
        </aside>
      </div>
    </>
  )
}
