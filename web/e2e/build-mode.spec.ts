import { expect, test, type Page } from '@playwright/test'

const expectedMode = process.env.LANEWAY_EXPECTED_BUILD_MODE
const password = 'compiled live password'
const principalId = '1'.repeat(32)
const sessionId = '2'.repeat(32)
const networkId = '3'.repeat(32)
const accessUserId = '6'.repeat(32)
const accessTeamId = '7'.repeat(32)
const csrfToken = 'c'.repeat(43)
const browserSessionCookieName = '__Host-laneway_admin_session'
const permissions = [
  'network.list', 'network.read', 'network.create', 'enrollment.issue', 'bootstrap_bundle.create',
  'node.read', 'node.manage', 'route.read', 'route.manage', 'acl.read', 'acl.manage', 'relay.read',
  'relay.manage', 'certificate.read', 'certificate.revoke', 'audit.read', 'audit.read_global', 'principal.manage',
  'session.manage_others', 'recovery.manage', 'root_token.rotate',
]

type Network = {
  network_id: string
  name: string
  ipv4_pool: string
  configuration_epoch: number
  created_at_unix_seconds: number
}

const controllerNetwork: Network = {
  network_id: networkId,
  name: 'Controller inventory canary',
  ipv4_pool: '100.90.0.0/24',
  configuration_epoch: 17,
  created_at_unix_seconds: 1_700_000_000,
}

function sessionView(activeSessionId = sessionId, username = 'console-owner') {
  const now = Math.floor(Date.now() / 1000)
  return {
    principal_id: principalId,
    username,
    role: 'owner',
    permissions,
    all_networks: true,
    network_ids: [],
    session_id: activeSessionId,
    idle_lifetime_seconds: 1800,
    idle_expires_at_unix_seconds: now + 1800,
    absolute_expires_at_unix_seconds: now + 28_800,
    csrf_token: csrfToken,
  }
}

function sessionHeaders(activeSessionId = sessionId) {
  const now = Math.floor(Date.now() / 1000)
  return {
    'X-Laneway-Session-ID': activeSessionId,
    'X-Laneway-Session-Idle-Expires-At': String(now + 1800),
    'X-Laneway-Session-Absolute-Expires-At': String(now + 28_800),
  }
}

function requestCookieValue(cookieHeader: string | undefined, name: string) {
  return cookieHeader?.split(';').map((value) => value.trim()).find((value) => value.startsWith(`${name}=`))?.slice(name.length + 1)
}

function browserSessionSetCookie(value: string) {
  return `${browserSessionCookieName}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict`
}

async function mockManagementApi(page: Page, networks: Network[], auditEvents: unknown[] = []) {
  const requests: Array<{ authorization?: string; csrf?: string; method: string; origin: string; path: string }> = []
  await page.route('**/v1/admin/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const headers = request.headers()
    requests.push({ authorization: headers.authorization, csrf: headers['x-laneway-csrf'], method: request.method(), origin: url.origin, path: `${url.pathname}${url.search}` })

    if (url.pathname === '/v1/admin/auth/session') return route.fulfill({ status: 401, json: { error: 'unauthorized' } })
    if (url.pathname === '/v1/admin/auth/state') return route.fulfill({ json: { state: 'sign_in' } })
    if (url.pathname === '/v1/admin/auth/login') {
      const body = request.postDataJSON() as { username?: string; password?: string }
      return body.username === 'console-owner' && body.password === password
        ? route.fulfill({ json: sessionView() })
        : route.fulfill({ status: 401, json: { error: 'unauthorized' } })
    }
    if (url.pathname === '/v1/admin/networks') return route.fulfill({ headers: sessionHeaders(), json: { networks } })
    if (url.pathname === '/v1/admin/audit') return route.fulfill({ headers: sessionHeaders(), json: { events: auditEvents } })

    const prefix = `/v1/admin/networks/${networkId}`
    const responses: Record<string, unknown> = {
      [`${prefix}/nodes`]: { nodes: [{ node_id: '4'.repeat(32), network_id: networkId, user_id: accessUserId, name: 'controller-node-canary', enabled_capabilities: 16, ipv4_address: '100.90.0.9', created_at_unix_seconds: 1_700_000_100, enrollment_class: 'durable' }] },
      [`${prefix}/routes`]: { routes: [{ route_id: '5'.repeat(32), network_id: networkId, node_id: '4'.repeat(32), prefix: '0.0.0.0/0', kind: 'exit', mode: 'nat', metric: 100, state: 'approved', created_at_unix_seconds: 1_700_000_100 }] },
      [`${prefix}/acl-rules`]: { acl_rules: [] },
      [`${prefix}/access-subjects`]: {
        users: [{ user_id: accessUserId, network_id: networkId, name: 'Private operator', enabled: true, created_at_unix_seconds: 1_700_000_100, updated_at_unix_seconds: 1_700_000_100 }],
        teams: [{ team_id: accessTeamId, network_id: networkId, name: 'Operations Team', created_at_unix_seconds: 1_700_000_100, updated_at_unix_seconds: 1_700_000_100 }],
        memberships: [{ network_id: networkId, team_id: accessTeamId, user_id: accessUserId, created_at_unix_seconds: 1_700_000_100 }],
        grants: [],
      },
      [`${prefix}/relays`]: { relays: [] },
      [`${prefix}/certificates`]: { certificates: [] },
      [`${prefix}/audit`]: { events: [] },
    }
    const response = responses[url.pathname]
    return response === undefined
      ? route.fulfill({ status: 404, json: { error: 'unexpected management request' } })
      : route.fulfill({ headers: sessionHeaders(), json: response })
  })
  return requests
}

async function signIn(page: Page, enteredPassword = password) {
  await page.goto('/sign-in')
  await page.getByLabel('Username').fill('console-owner')
  await page.getByLabel('Password').fill(enteredPassword)
  await page.getByRole('button', { name: 'Sign in' }).click()
}

test('compiled artifact preserves its declared authentication boundary', async ({ page }) => {
  expect(['live', 'demo']).toContain(expectedMode)
  if (expectedMode === 'live') await mockManagementApi(page, [])
  await page.addInitScript(() => {
    window.localStorage.setItem('laneway-console-admin-token', 'legacy-secret')
    window.sessionStorage.setItem('laneway-console-operator', 'Legacy Name')
  })
  await page.goto('/sign-in')
  await expect(page.locator('link[rel="icon"]')).toHaveAttribute('href', '/laneway-mark.svg')
  await expect(page.locator('link[rel="apple-touch-icon"]')).toHaveAttribute('href', '/apple-touch-icon.png')
  await expect(page.locator('link[rel="manifest"]')).toHaveAttribute('href', '/site.webmanifest')
  await expect(page.locator('.brand-mark')).toHaveAttribute('src', '/laneway-mark.svg')
  expect(await page.evaluate(() => [window.localStorage.getItem('laneway-console-admin-token'), window.sessionStorage.getItem('laneway-console-operator')])).toEqual([null, null])

  if (expectedMode === 'live') {
    await expect(page.getByRole('heading', { name: 'Sign in to Laneway' })).toBeVisible()
    await expect(page.getByLabel('Username')).toBeVisible()
    await expect(page.getByLabel('Password')).toBeVisible()
    await expect(page.getByLabel(/administrator token|controller address|operator label/i)).toHaveCount(0)
    await expect(page.getByRole('note', { name: 'Demo data notice' })).toHaveCount(0)
  } else {
    await expect(page).toHaveURL(/\/overview$/)
    await expect(page.getByRole('note', { name: 'Demo data notice' })).toBeVisible()
    await expect(page.getByLabel('Signed in administrator')).toHaveCount(0)
  }
})

test('compiled live artifact refuses an authentication redirect before sending credentials off origin', async ({ page }) => {
  test.skip(expectedMode !== 'live', 'Live artifact contract')
  let redirectedRequestObserved = false
  await page.route('https://redirect.invalid/**', async (route) => {
    redirectedRequestObserved = true
    await route.fulfill({ json: sessionView() })
  })
  await page.route('**/v1/admin/**', async (route) => {
    const url = new URL(route.request().url())
    if (url.pathname === '/v1/admin/auth/session') return route.fulfill({ status: 401, json: { error: 'unauthorized' } })
    if (url.pathname === '/v1/admin/auth/state') return route.fulfill({ json: { state: 'sign_in' } })
    if (url.pathname === '/v1/admin/auth/login') {
      return route.fulfill({ status: 307, headers: { Location: 'https://redirect.invalid/collect' }, body: '' })
    }
    return route.fulfill({ status: 404, json: { error: 'unexpected management request' } })
  })

  await signIn(page)

  await expect(page.getByLabel('Password')).toHaveValue('')
  await expect(page.getByRole('alert').filter({ hasText: 'Failed to fetch' })).toBeVisible()
  await expect(page).toHaveURL(/\/sign-in$/)
  expect(redirectedRequestObserved).toBe(false)
})

test('compiled live artifact uses same-origin cookie transport and real permissioned inventory', async ({ page }) => {
  test.skip(expectedMode !== 'live', 'Live artifact contract')
  const requests = await mockManagementApi(page, [controllerNetwork])

  await signIn(page, 'rejected password value')
  await expect(page.getByText('The username or password was rejected.')).toBeVisible()
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/overview$/)
  await expect(page.getByText('1 Network', { exact: true })).toBeVisible()
  await expect(page.getByLabel('Signed in administrator')).toContainText('console-owner')
  await page.getByRole('link', { name: 'Networks', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Networks', exact: true, level: 1 })).toBeVisible()
  const networkViews = page.getByRole('navigation', { name: 'Network workspace views' })
  await networkViews.getByRole('link', { name: 'Nodes' }).click()
  await expect(page.getByText('controller-node-canary', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Network exit', { exact: true })).toBeVisible()
  await networkViews.getByRole('link', { name: 'Connectivity' }).click()
  await expect(page.getByText('Connection data unavailable', { exact: true })).toBeVisible()
  await networkViews.getByRole('link', { name: 'Networks', exact: true }).click()
  await page.getByRole('button', { name: 'Add Network' }).click()
  await expect(page.getByRole('heading', { name: 'Create Network' })).toBeVisible()
  await expect(page.getByLabel('IPv4 address pool')).toBeVisible()
  await page.getByRole('button', { name: 'Cancel' }).click()
  await page.getByRole('link', { name: 'People' }).click()
  await expect(page.getByRole('heading', { name: 'People' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Users' })).toHaveAttribute('aria-current', 'page')
  await expect(page.getByText('Private operator', { exact: true })).toBeVisible()
  await page.getByRole('link', { name: 'Teams' }).click()
  await expect(page.getByRole('heading', { name: 'People' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'People' })).toHaveAttribute('aria-current', 'page')
  await expect(page.getByRole('link', { name: 'Teams' })).toHaveAttribute('aria-current', 'page')
  await expect(page.getByText('Operations Team', { exact: true })).toBeVisible()

  expect(requests.length).toBeGreaterThan(0)
  expect(requests.every((request) => request.authorization === undefined)).toBe(true)
  expect(new Set(requests.map((request) => request.origin))).toEqual(new Set([new URL(page.url()).origin]))
  expect(requests.filter((request) => request.method === 'GET').every((request) => request.csrf === undefined)).toBe(true)
})

test('compiled live artifact keeps multiple Networks in one workspace', async ({ page }) => {
  test.skip(expectedMode !== 'live', 'Live artifact contract')
  const requests = await mockManagementApi(page, [controllerNetwork, { ...controllerNetwork, network_id: '5'.repeat(32), name: 'Second controller canary' }])

  await signIn(page)
  await expect(page.getByLabel('Selected network')).toHaveCount(0)
  await page.getByRole('link', { name: 'Networks', exact: true }).click()
  await expect(page.getByRole('heading', { name: '2 Networks' })).toBeVisible()
  const networkViews = page.getByRole('navigation', { name: 'Network workspace views' })
  await networkViews.getByRole('link', { name: 'Nodes' }).click()
  await expect(page.getByText('controller-node-canary', { exact: true }).first()).toBeVisible()
  await networkViews.getByRole('link', { name: 'Connectivity' }).click()
  await page.getByRole('button', { name: 'Connect Network' }).click()
  await expect(page.getByLabel('Destination Network')).toHaveValue('5'.repeat(32))
  await expect(page.getByLabel('Initial access')).toHaveValue('Deny all traffic')
  await expect(page.getByText('No traffic flows until access and routes are configured.')).toBeVisible()
  expect(requests.some((request) => request.path === '/v1/admin/audit?limit=250')).toBe(true)
  expect(requests.some((request) => request.path.includes(`/networks/${networkId}/audit`))).toBe(false)
  await expect(page.getByRole('note', { name: 'Demo data notice' })).toHaveCount(0)
})

test('compiled live audit keeps the event detail visible while the event stream scrolls', async ({ page }) => {
  test.skip(expectedMode !== 'live', 'Live artifact contract')
  await page.setViewportSize({ width: 1440, height: 900 })
  const now = Math.floor(Date.now() / 1000)
  const events = Array.from({ length: 40 }, (_, index) => ({
    event_id: (index + 10).toString(16).padStart(32, '0'),
    network_id: networkId,
    actor_kind: 'system',
    action: 'node.update',
    target_type: 'node',
    target_id: '4'.repeat(32),
    details: { sequence: index + 1 },
    created_at_unix_seconds: now - index * 60,
  }))
  await mockManagementApi(page, [controllerNetwork], events)

  await signIn(page)
  await page.getByRole('link', { name: 'Audit', exact: true }).click()
  await expect(page.locator('.audit-day > button')).toHaveCount(events.length)
  const stream = page.locator('.audit-stream-scroll')
  const inspector = page.getByLabel('Selected audit event detail')
  await expect(stream).toBeVisible()
  await expect(inspector).toBeVisible()

  await stream.evaluate((element) => { element.scrollTop = element.scrollHeight })
  expect(await stream.evaluate((element) => element.scrollTop)).toBeGreaterThan(0)
  expect(await page.evaluate(() => window.scrollY)).toBe(0)
  const inspectorBox = await inspector.boundingBox()
  expect(inspectorBox).not.toBeNull()
  expect((inspectorBox?.y ?? 0) + (inspectorBox?.height ?? 0)).toBeLessThanOrEqual(900)

  await page.locator('.audit-day > button').last().click()
  await expect(inspector.getByText(events.at(-1)?.event_id ?? '', { exact: true })).toBeVisible()
  expect(await page.evaluate(() => window.scrollY)).toBe(0)
})

test('compiled live artifact keeps the workspace usable on a compact viewport and across themes', async ({ page }) => {
  test.skip(expectedMode !== 'live', 'Live artifact contract')
  await page.setViewportSize({ width: 390, height: 844 })
  await mockManagementApi(page, [controllerNetwork])

  await signIn(page)
  await expect(page).toHaveURL(/\/overview$/)
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Use dark theme' })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true)

  await page.getByRole('button', { name: 'Use dark theme' }).click()
  await expect(page.getByRole('button', { name: 'Use light theme' })).toBeVisible()
  expect(await page.evaluate(() => ({ theme: document.documentElement.dataset.theme, stored: window.localStorage.getItem('laneway-console-theme') }))).toEqual({ theme: 'dark', stored: 'dark' })

  await page.getByRole('link', { name: 'Networks', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Networks', exact: true })).toBeVisible()
  await page.getByRole('navigation', { name: 'Network workspace views' }).getByRole('link', { name: 'Nodes' }).click()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true)
  await page.getByRole('link', { name: 'People' }).click()
  await expect(page.getByRole('heading', { name: 'People' })).toBeVisible()
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0)
})

test('a two-tab logout wins over a racing session rotation', async ({ context }) => {
  test.skip(expectedMode !== 'live', 'Live artifact contract')
  let revoked = false
  let releaseRotation!: () => void
  let markRotationStarted!: () => void
  const rotationRelease = new Promise<void>((resolve) => { releaseRotation = resolve })
  const rotationStarted = new Promise<void>((resolve) => { markRotationStarted = resolve })

  await context.route('**/v1/admin/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    if (url.pathname === '/v1/admin/auth/session') {
      return revoked ? route.fulfill({ status: 401, json: { error: 'invalid session family' } }) : route.fulfill({ json: sessionView() })
    }
    if (url.pathname === '/v1/admin/auth/state') return route.fulfill({ json: { state: 'sign_in' } })
    if (url.pathname === '/v1/admin/auth/session/rotate') {
      markRotationStarted()
      await rotationRelease
      return revoked ? route.fulfill({ status: 401, json: { error: 'invalid session family' } }) : route.fulfill({ json: sessionView('6'.repeat(32)) })
    }
    if (url.pathname === '/v1/admin/auth/logout') {
      revoked = true
      return route.fulfill({ status: 204, body: '' })
    }
    if (url.pathname === '/v1/admin/networks') return route.fulfill({ headers: sessionHeaders(), json: { networks: [] } })
    if (url.pathname === '/v1/admin/audit') return route.fulfill({ headers: sessionHeaders(), json: { events: [] } })
    return route.fulfill({ status: 404, json: { error: 'unexpected management request' } })
  })

  const rotatingTab = await context.newPage()
  const logoutTab = await context.newPage()
  await Promise.all([rotatingTab.goto('/overview'), logoutTab.goto('/overview')])
  await expect(rotatingTab.getByLabel('Signed in administrator')).toContainText('console-owner')
  await expect(logoutTab.getByLabel('Signed in administrator')).toContainText('console-owner')

  await rotatingTab.getByRole('button', { name: 'Refresh session' }).click()
  await rotationStarted
  await logoutTab.getByRole('button', { name: 'Sign out' }).click()
  await expect(logoutTab.getByRole('heading', { name: 'Sign in to Laneway' })).toBeVisible()
  releaseRotation()
  await expect(rotatingTab.getByRole('heading', { name: 'Sign in to Laneway' })).toBeVisible()
  await rotatingTab.reload()
  await expect(rotatingTab.getByRole('heading', { name: 'Sign in to Laneway' })).toBeVisible()
  await expect(rotatingTab.getByLabel('Signed in administrator')).toHaveCount(0)
})

test('a stale rotation Set-Cookie is reconciled across two tabs after a newer sign-in', async ({ context }) => {
  test.skip(expectedMode !== 'live', 'Live artifact contract')
  const cookieA = 'cookie-a'
  const cookieB = 'cookie-b'
  const cookieC = 'cookie-c'
  const sessionA = sessionId
  const sessionB = '6'.repeat(32)
  const sessionC = '7'.repeat(32)
  const sessions = new Map([
    [cookieA, sessionView(sessionA, 'session-a')],
    [cookieB, sessionView(sessionB, 'session-b')],
    [cookieC, sessionView(sessionC, 'session-c')],
  ])
  const restoredCookies: Array<string | undefined> = []
  let releaseRotation!: () => void
  let markRotationStarted!: () => void
  const rotationRelease = new Promise<void>((resolve) => { releaseRotation = resolve })
  const rotationStarted = new Promise<void>((resolve) => { markRotationStarted = resolve })

  await context.addCookies([{ name: browserSessionCookieName, value: cookieA, domain: '127.0.0.1', path: '/', httpOnly: true, secure: true, sameSite: 'Strict' }])
  await context.route('**/v1/admin/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const activeCookie = requestCookieValue(request.headers().cookie, browserSessionCookieName)
    const activeSession = activeCookie ? sessions.get(activeCookie) : undefined
    if (url.pathname === '/v1/admin/auth/session') {
      restoredCookies.push(activeCookie)
      return activeSession
        ? route.fulfill({ json: activeSession })
        : route.fulfill({ status: 401, json: { error: 'unauthorized' } })
    }
    if (url.pathname === '/v1/admin/auth/state') return route.fulfill({ json: { state: 'sign_in' } })
    if (url.pathname === '/v1/admin/auth/login') {
      return route.fulfill({ headers: { 'Set-Cookie': browserSessionSetCookie(cookieB) }, json: sessions.get(cookieB) })
    }
    if (url.pathname === '/v1/admin/auth/session/rotate') {
      markRotationStarted()
      await rotationRelease
      return route.fulfill({ headers: { 'Set-Cookie': browserSessionSetCookie(cookieC) }, json: sessions.get(cookieC) })
    }
    if (url.pathname === '/v1/admin/auth/logout') {
      return route.fulfill({ status: 204, headers: { 'Set-Cookie': `${browserSessionCookieName}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict` }, body: '' })
    }
    if (url.pathname === '/v1/admin/networks') {
      return activeSession
        ? route.fulfill({ headers: sessionHeaders(activeSession.session_id), json: { networks: [] } })
        : route.fulfill({ status: 401, json: { error: 'unauthorized' } })
    }
    if (url.pathname === '/v1/admin/audit') {
      return activeSession
        ? route.fulfill({ headers: sessionHeaders(activeSession.session_id), json: { events: [] } })
        : route.fulfill({ status: 401, json: { error: 'unauthorized' } })
    }
    return route.fulfill({ status: 404, json: { error: 'unexpected management request' } })
  })

  const rotatingTab = await context.newPage()
  const loginTab = await context.newPage()
  await Promise.all([rotatingTab.goto('/overview'), loginTab.goto('/overview')])
  await expect(rotatingTab.getByLabel('Signed in administrator')).toContainText('session-a')
  await expect(loginTab.getByLabel('Signed in administrator')).toContainText('session-a')

  await rotatingTab.getByRole('button', { name: 'Refresh session' }).click()
  await rotationStarted
  await loginTab.getByRole('button', { name: 'Sign out' }).click()
  await expect(loginTab.getByRole('heading', { name: 'Sign in to Laneway' })).toBeVisible()
  await loginTab.getByLabel('Username').fill('console-owner')
  await loginTab.getByLabel('Password').fill(password)
  await loginTab.getByRole('button', { name: 'Sign in' }).click()
  await expect(loginTab.getByLabel('Signed in administrator')).toContainText('session-b')
  await expect(rotatingTab.getByLabel('Signed in administrator')).toContainText('session-b')

  releaseRotation()

  await expect(rotatingTab.getByLabel('Signed in administrator')).toContainText('session-c')
  await expect(loginTab.getByLabel('Signed in administrator')).toContainText('session-c')
  const cookie = (await context.cookies()).find((candidate) => candidate.name === browserSessionCookieName)
  expect(cookie?.value).toBe(cookieC)
  expect(restoredCookies).toContain(cookieB)
  expect(restoredCookies).toContain(cookieC)

  await Promise.all([rotatingTab.reload(), loginTab.reload()])
  await expect(rotatingTab.getByLabel('Signed in administrator')).toContainText('session-c')
  await expect(loginTab.getByLabel('Signed in administrator')).toContainText('session-c')
})
