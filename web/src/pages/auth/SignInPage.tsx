import { useState, type FormEvent } from 'react'
import { LockKeyhole } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button, Callout, Field } from '../../components/ui'
import { controllerOrigin, useControlPlane } from '../../lib/control-plane'
import './auth.css'

function isControllerAddress(value: string) {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:'
  } catch {
    return false
  }
}

export function SignInPage() {
  const navigate = useNavigate()
  const { signIn, authError, authPending, live } = useControlPlane()
  const [controller, setController] = useState(() => live ? controllerOrigin() : 'https://controller.home.example')
  const [token, setToken] = useState('')
  const [submitted, setSubmitted] = useState(false)

  const controllerError = submitted && !isControllerAddress(controller)
    ? 'Enter a complete HTTP or HTTPS controller address.'
    : undefined
  const tokenError = submitted && token.trim().length < 8
    ? 'Enter an administrator token with at least 8 characters.'
    : undefined

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitted(true)
    if (isControllerAddress(controller) && token.trim().length >= 8) {
      const accepted = await signIn(token)
      if (accepted) navigate('/overview')
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-stage" aria-labelledby="sign-in-title">
        <div className="auth-brand" aria-label="Laneway">
          <span className="auth-brand__mark" aria-hidden="true"><i /><i /><i /></span>
          <span>Laneway</span>
        </div>

        <div className="auth-layout">
          <div className="auth-intro">
            <h1 id="sign-in-title">Sign in to Laneway</h1>
          </div>

          <form className="auth-panel" noValidate onSubmit={handleSubmit}>
            <div className="auth-panel__heading"><h2>Administrator access</h2></div>
            <Field label="Controller address" hint={live ? 'Fixed for this deployment.' : undefined} error={controllerError}>
              <input
                aria-invalid={Boolean(controllerError)}
                autoComplete="url"
                disabled={live}
                inputMode="url"
                onChange={(event) => setController(event.target.value)}
                placeholder="https://controller.example.com"
                type="url"
                value={controller}
              />
            </Field>
            <Field label="Administrator token" hint="Stored for this browser session and sent with controller requests." error={tokenError}>
              <input
                aria-invalid={Boolean(tokenError)}
                autoComplete="current-password"
                onChange={(event) => setToken(event.target.value)}
                placeholder="Enter administrator token"
                type="password"
                value={token}
              />
            </Field>
            {authError ? <Callout tone="danger">{authError}</Callout> : null}
            <Button className="auth-submit" type="submit" variant="primary" disabled={authPending}>
              <LockKeyhole aria-hidden="true" size={17} /> {authPending ? 'Signing in…' : 'Sign in'}
            </Button>
            <Button className="auth-sso" type="button" disabled title="Single sign-on is not supported by this controller build">SSO unavailable</Button>
          </form>
        </div>
      </section>
    </main>
  )
}
