import { useEffect, useState, type FormEvent } from 'react'
import { Button, Callout, Field, FormStack, PageHeader, Status } from '../../components/ui'
import { useControlPlane } from '../../lib/control-plane'

const endpoint = '/v1/admin/integrations/twingate'

type TwingateConnection = { tenant: string | null; verified_at_unix_seconds: number | null }
type TwingateConnectionRequest = { tenant: string; api_token: string }

type Action = 'save' | 'test' | 'disconnect'

const actionMessages = {
  save: 'Connection verified and saved.',
  test: 'Connection verified.',
  disconnect: 'Twingate disconnected.',
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : 'Twingate setup could not be completed.'
}

export function TwingatePage() {
  const { request } = useControlPlane()
  const [connection, setConnection] = useState<TwingateConnection>()
  const [tenant, setTenant] = useState('')
  const [apiToken, setApiToken] = useState('')
  const [action, setAction] = useState<Action>()
  const [loadAttempt, setLoadAttempt] = useState(0)
  const [loadError, setLoadError] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    void request<TwingateConnection>(endpoint, { signal: controller.signal }).then((saved) => {
      if (controller.signal.aborted) return
      setConnection(saved)
      setTenant(saved.tenant ?? '')
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setLoadError(errorMessage(failure))
    })
    return () => controller.abort()
  }, [loadAttempt, request])

  async function apply(next: Action, body?: TwingateConnectionRequest) {
    setAction(next)
    setError('')
    setNotice('')
    try {
      const path = next === 'test' ? endpoint + '/test' : endpoint
      const method = { save: 'PUT', test: 'POST', disconnect: 'DELETE' }[next]
      const saved = await request<TwingateConnection>(path, { method, body })
      setConnection(saved)
      if (next !== 'test') {
        setTenant(saved.tenant ?? '')
        setApiToken('')
      }
      setNotice(actionMessages[next])
    } catch (failure) {
      setError(errorMessage(failure))
    } finally {
      setAction(undefined)
    }
  }

  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!tenant.trim() || !apiToken.trim() || action) return
    void apply('save', { tenant: tenant.trim(), api_token: apiToken.trim() })
  }

  return <>
    <PageHeader title="Twingate" />
    {loadError ? <>
      <div role="alert"><Callout tone="danger">{loadError}</Callout></div>
      <Button onClick={() => { setLoadError(''); setLoadAttempt(loadAttempt + 1) }}>Retry</Button>
    </> : !connection ? <p role="status">Loading Twingate connection…</p> :
      <FormStack onSubmit={save}>
        <div className="button-row">
          <Status tone={connection.tenant ? 'positive' : 'muted'}>{connection.tenant ? 'Saved' : 'Disconnected'}</Status>
          {connection.tenant ? <strong>{connection.tenant}.twingate.com</strong> : null}
        </div>
        {connection.verified_at_unix_seconds !== null ? <p>
          Last verified <time dateTime={new Date(connection.verified_at_unix_seconds * 1000).toISOString()}>
            {new Date(connection.verified_at_unix_seconds * 1000).toLocaleString()}
          </time>
        </p> : null}
        <Field label="Twingate network" hint="Enter the name before .twingate.com.">
          <input autoCapitalize="none" autoComplete="off" disabled={Boolean(action)} maxLength={63} onChange={(event) => setTenant(event.target.value)} placeholder="acme" required spellCheck={false} value={tenant} />
        </Field>
        <Field label={connection.tenant ? 'New API token' : 'API token'} hint={<>Generate a Read only token in Twingate under Settings → API. <a href="https://www.twingate.com/docs/api-overview#getting-started" rel="noreferrer" target="_blank">Token setup guide</a></>}>
          <input autoComplete="new-password" disabled={Boolean(action)} maxLength={4096} onChange={(event) => setApiToken(event.target.value)} required type="password" value={apiToken} />
        </Field>
        {error ? <div role="alert"><Callout tone="danger">{error}</Callout></div> : null}
        {notice ? <p role="status">{notice}</p> : null}
        <div className="button-row">
          <Button disabled={Boolean(action) || !tenant.trim() || !apiToken.trim()} type="submit" variant="primary">{action === 'save' ? 'Testing and saving…' : 'Test and save'}</Button>
          {connection.tenant ? <>
            <Button disabled={Boolean(action)} onClick={() => void apply('test')}>{action === 'test' ? 'Testing…' : 'Test saved connection'}</Button>
            <Button disabled={Boolean(action)} onClick={() => void apply('disconnect')} variant="quiet">{action === 'disconnect' ? 'Disconnecting…' : 'Disconnect'}</Button>
          </> : null}
        </div>
      </FormStack>
    }
  </>
}
