import { useState, type FormEvent, type ReactNode } from 'react'
import { LockKeyhole, RefreshCw } from 'lucide-react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Button, Callout, Field } from '../../components/ui'
import { ThemeToggle } from '../../components/Theme'
import { BrandMark } from '../../components/BrandMark'
import { useControlPlane } from '../../lib/control-plane'
import { safeReturnPath } from '../../lib/safe-navigation'
import './auth.css'

function AuthFrame({ title, children }: { title: string; children: ReactNode }) {
  return <main className="auth-page">
    <section className="auth-stage" aria-labelledby="auth-title">
      <ThemeToggle className="auth-theme-toggle" />
      <div className="auth-brand" aria-label="Laneway">
        <BrandMark className="auth-brand__mark" />
        <span>Laneway</span>
      </div>
      <div className="auth-layout">
        <div className="auth-intro"><h1 id="auth-title">{title}</h1></div>
        {children}
      </div>
    </section>
  </main>
}

function useReturnPath() {
  const location = useLocation()
  const state = location.state as { from?: unknown } | null
  return safeReturnPath(state?.from)
}

export function AuthenticationUnavailablePage() {
  const { authError, authPending, retryAuthentication } = useControlPlane()
  return <AuthFrame title="Controller unavailable">
    <section className="auth-panel">
      <div role="alert"><Callout tone="danger">{authError || 'Authentication is unavailable.'}</Callout></div>
      <Button className="auth-submit" type="button" variant="primary" disabled={authPending} onClick={() => void retryAuthentication()}>
        <RefreshCw aria-hidden="true" size={17} /> Retry
      </Button>
    </section>
  </AuthFrame>
}

export function SetupRequiredPage() {
  const { authState, live, retryAuthentication } = useControlPlane()
  if (!live || authState === 'authenticated') return <Navigate to="/overview" replace />
  if (authState === 'checking') return <AuthFrame title="Checking setup"><p className="auth-panel" role="status">Checking controller setup…</p></AuthFrame>
  if (authState === 'unavailable') return <AuthenticationUnavailablePage />
  if (authState === 'anonymous') return <Navigate to="/sign-in" replace />
  return <AuthFrame title="Setup required">
    <section className="auth-panel">
      <p>Complete administrator setup on the control node.</p>
      <Button className="auth-submit" type="button" variant="primary" onClick={() => void retryAuthentication()}>
        <RefreshCw aria-hidden="true" size={17} /> Retry
      </Button>
    </section>
  </AuthFrame>
}

export function SignInPage() {
  const navigate = useNavigate()
  const destination = useReturnPath()
  const { signIn, authError, authPending, authState, live } = useControlPlane()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitted, setSubmitted] = useState(false)

  if (!live || authState === 'authenticated') return <Navigate to={destination} replace />
  if (authState === 'checking') return <AuthFrame title="Checking session"><p className="auth-panel" role="status">Checking administrator session…</p></AuthFrame>
  if (authState === 'bootstrap_required') return <Navigate to="/setup" replace />
  if (authState === 'unavailable') return <AuthenticationUnavailablePage />

  const normalizedUsername = username.trim()
  const passwordBytes = new TextEncoder().encode(password).length
  const usernameInvalid = normalizedUsername.length < 3 || normalizedUsername.length > 64 || !/^[a-z0-9](?:[a-z0-9._-]{1,62}[a-z0-9])?$/.test(normalizedUsername)
  const passwordInvalid = passwordBytes < 15 || passwordBytes > 1024
  const usernameError = submitted && usernameInvalid
    ? 'Enter a valid administrator username.'
    : undefined
  const passwordError = submitted && passwordInvalid
    ? 'Enter your administrator password.'
    : undefined

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitted(true)
    if (usernameInvalid || passwordInvalid) return
    const accepted = await signIn(normalizedUsername, password)
    setPassword('')
    if (accepted) navigate(destination, { replace: true })
  }

  return <AuthFrame title="Sign in to Laneway">
    <form className="auth-panel" noValidate onSubmit={handleSubmit}>
      <Field label="Username" error={usernameError}>
        <input
          aria-invalid={Boolean(usernameError)}
          autoCapitalize="none"
          autoComplete="username"
          autoFocus
          onChange={(event) => setUsername(event.target.value)}
          spellCheck={false}
          value={username}
        />
      </Field>
      <Field label="Password" error={passwordError}>
        <input
          aria-invalid={Boolean(passwordError)}
          autoComplete="current-password"
          onChange={(event) => setPassword(event.target.value)}
          type="password"
          value={password}
        />
      </Field>
      {authError ? <div role="alert"><Callout tone="danger">{authError}</Callout></div> : null}
      <Button className="auth-submit" type="submit" variant="primary" disabled={authPending}>
        <LockKeyhole aria-hidden="true" size={17} /> {authPending ? 'Signing in…' : 'Sign in'}
      </Button>
    </form>
  </AuthFrame>
}
