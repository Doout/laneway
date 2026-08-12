import { expect, test, type Page } from '@playwright/test'

const expectedMode = process.env.LANEWAY_EXPECTED_BUILD_MODE
const adminToken = 'compiled-live-admin-token'

type Network = {
  network_id: string
  name: string
  ipv4_pool: string
  configuration_epoch: number
  created_at_unix_seconds: number
}

const controllerNetwork: Network = {
  network_id: 'net_controller_canary',
  name: 'Controller inventory canary',
  ipv4_pool: '100.90.0.0/24',
  configuration_epoch: 17,
  created_at_unix_seconds: 1_700_000_000,
}

async function mockManagementApi(page: Page, networks: Network[]) {
  const requests: Array<{ authorization?: string; origin: string; path: string }> = []

  await page.route('**/v1/admin/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const authorization = request.headers().authorization
    requests.push({ authorization, origin: url.origin, path: `${url.pathname}${url.search}` })

    if (authorization !== `Bearer ${adminToken}`) {
      await route.fulfill({ status: 401, json: { error: 'unauthorized' } })
      return
    }

    if (url.pathname === '/v1/admin/networks') {
      await route.fulfill({ json: { networks: url.searchParams.get('limit') === '1' ? networks.slice(0, 1) : networks } })
      return
    }

    const networkPrefix = `/v1/admin/networks/${controllerNetwork.network_id}`
    const responses: Record<string, unknown> = {
      [`${networkPrefix}/nodes`]: {
        nodes: [{
          node_id: 'node_controller_canary',
          network_id: controllerNetwork.network_id,
          name: 'controller-node-canary',
          enabled_capabilities: 8,
          ipv4_address: '100.90.0.9',
          created_at_unix_seconds: 1_700_000_100,
          enrollment_class: 'durable',
        }],
      },
      [`${networkPrefix}/routes`]: { routes: [] },
      [`${networkPrefix}/acl-rules`]: { acl_rules: [] },
      [`${networkPrefix}/relays`]: { relays: [] },
      [`${networkPrefix}/certificates`]: { certificates: [] },
      [`${networkPrefix}/audit`]: { events: [] },
    }
    const response = responses[url.pathname]
    await route.fulfill(response === undefined
      ? { status: 404, json: { error: 'unexpected management request' } }
      : { json: response })
  })

  return requests
}

async function signIn(page: Page, token = adminToken) {
  await page.goto('/sign-in')
  await page.getByLabel('Administrator token').fill(token)
  await page.getByRole('button', { name: 'Sign in' }).click()
}

function expectAuthenticatedSameOriginRequests(page: Page, requests: Awaited<ReturnType<typeof mockManagementApi>>) {
  expect(requests.length).toBeGreaterThan(0)
  expect(new Set(requests.map(request => request.authorization))).toEqual(new Set([`Bearer ${adminToken}`]))
  expect(new Set(requests.map(request => request.origin))).toEqual(new Set([new URL(page.url()).origin]))
}

test('compiled artifact preserves its declared data boundary', async ({ page }) => {
  expect(['live', 'demo']).toContain(expectedMode)
  await page.addInitScript(() => window.sessionStorage.setItem('laneway-console-operator', 'Legacy label'))
  await page.goto('/sign-in')
  const controllerAddress = page.getByLabel('Controller address')
  await expect(page.getByLabel('Session label')).toHaveCount(0)
  expect(await page.evaluate(() => window.sessionStorage.getItem('laneway-console-operator'))).toBeNull()

  if (expectedMode === 'live') {
    await expect(controllerAddress).toBeDisabled()
    await expect(page.getByRole('note', { name: 'Demo data notice' })).toHaveCount(0)
    return
  }

  await expect(controllerAddress).toBeEnabled()
  await page.getByLabel('Administrator token').fill('demo-administrator-token')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('note', { name: 'Demo data notice' })).toBeVisible()
})

test('compiled live artifact authenticates against its same-origin controller inventory', async ({ page }) => {
  test.skip(expectedMode !== 'live', 'Live artifact contract')
  const requests = await mockManagementApi(page, [controllerNetwork])

  await signIn(page, 'rejected-admin-token')
  await expect(page.getByText('The administrator token was rejected.', { exact: true })).toBeVisible()
  expect(requests[0]).toMatchObject({ authorization: 'Bearer rejected-admin-token' })

  await page.getByLabel('Administrator token').fill(adminToken)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/overview$/)
  await expect(page.getByText(controllerNetwork.name, { exact: true }).first()).toBeVisible()
  await expect(page.locator('.system-bar').getByText('Inventory loaded', { exact: true })).toBeVisible()
  await expect(page.getByRole('note', { name: 'Demo data notice' })).toHaveCount(0)

  await page.getByRole('link', { name: 'Nodes' }).click()
  await expect(page.getByRole('heading', { name: '1 Nodes' })).toBeVisible()
  await expect(page.getByText('controller-node-canary', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('operator-laptop', { exact: true })).toHaveCount(0)
  await expect(page.getByText('atlas-gateway', { exact: true })).toHaveCount(0)

  const acceptedRequests = requests.filter(request => request.authorization === `Bearer ${adminToken}`)
  expectAuthenticatedSameOriginRequests(page, acceptedRequests)
})

test('compiled live artifact keeps a zero-network controller empty', async ({ page }) => {
  test.skip(expectedMode !== 'live', 'Live artifact contract')
  const requests = await mockManagementApi(page, [])

  await signIn(page)
  await expect(page).toHaveURL(/\/overview$/)
  await expect(page.locator('.system-bar').getByText('Inventory loaded', { exact: true })).toBeVisible()
  await page.getByRole('link', { name: 'Nodes' }).click()
  await expect(page.getByRole('heading', { name: '0 Nodes' })).toBeVisible()
  await expect(page.getByRole('note', { name: 'Demo data notice' })).toHaveCount(0)
  await expect(page.getByText('operator-laptop', { exact: true })).toHaveCount(0)
  await expect(page.getByText('atlas-gateway', { exact: true })).toHaveCount(0)

  expect(requests.map(request => request.path)).toEqual([
    '/v1/admin/networks?limit=1',
    '/v1/admin/networks?limit=100',
  ])
  expectAuthenticatedSameOriginRequests(page, requests)
})

test('compiled live artifact fails closed for a multi-network controller', async ({ page }) => {
  test.skip(expectedMode !== 'live', 'Live artifact contract')
  const requests = await mockManagementApi(page, [
    controllerNetwork,
    { ...controllerNetwork, network_id: 'net_second_canary', name: 'Second controller canary' },
  ])

  await signIn(page)
  await expect(page.getByRole('alert')).toContainText('This console supports one network')
  await expect(page.getByRole('heading', { name: 'Overview' })).toHaveCount(0)
  await expect(page.getByRole('note', { name: 'Demo data notice' })).toHaveCount(0)
  expect(requests.map(request => request.path)).toEqual([
    '/v1/admin/networks?limit=1',
    '/v1/admin/networks?limit=100',
  ])
  expectAuthenticatedSameOriginRequests(page, requests)
})
