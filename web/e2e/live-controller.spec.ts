import { expect, test } from '@playwright/test'

const liveURL = process.env.LANEWAY_LIVE_E2E_URL
const username = process.env.LANEWAY_LIVE_E2E_USERNAME
const password = process.env.LANEWAY_LIVE_E2E_PASSWORD
const requestedNetworkId = process.env.LANEWAY_LIVE_E2E_NETWORK_ID
const controllerHost = liveURL ? new URL(liveURL).host : ''

// This file handles real credentials and one-time secrets. Never persist a
// browser recording or failure capture containing them.
test.use({ baseURL: liveURL, ignoreHTTPSErrors: true, trace: 'off', screenshot: 'off', video: 'off' })

test.describe('live controller console', () => {
  test.skip(!liveURL || !username || !password, 'Set LANEWAY_LIVE_E2E_URL, LANEWAY_LIVE_E2E_USERNAME, and LANEWAY_LIVE_E2E_PASSWORD to run against a controller.')

  test('authenticates with a browser session, loads real inventory, and issues real one-time credentials', async ({ page }) => {
    await page.addInitScript(() => {
      window.localStorage.setItem('laneway-console-admin-token', 'legacy-secret')
      window.sessionStorage.setItem('laneway-console-operator', 'Legacy Name')
    })
    await page.goto('/sign-in')
    expect(await page.evaluate(() => [window.localStorage.getItem('laneway-console-admin-token'), window.sessionStorage.getItem('laneway-console-operator')])).toEqual([null, null])
    await expect(page.getByLabel(/administrator token|controller address|operator label/i)).toHaveCount(0)
    if (await page.getByLabel('Username').isVisible()) {
      await page.getByLabel('Username').fill(username!)
      await page.getByLabel('Password').fill(password!)
      await page.getByRole('button', { name: 'Sign in' }).click()
    }

    await expect(page).toHaveURL(/\/overview$/)
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()
    await expect(page.getByLabel('Signed in administrator')).toContainText(username!)
    await expect(page.getByRole('note', { name: 'Demo data notice' })).toHaveCount(0)
    const networksResponse = await page.request.get('/v1/admin/networks?limit=100')
    expect(networksResponse.ok()).toBeTruthy()
    const networkResult = await networksResponse.json() as { networks: Array<{ network_id: string; name: string }> }
    expect(networkResult.networks.length).toBeGreaterThan(0)
    const selectedNetwork = requestedNetworkId
      ? networkResult.networks.find((network) => network.network_id === requestedNetworkId)
      : networkResult.networks.at(0)
    expect(selectedNetwork).toBeDefined()
    await expect(page.getByText(selectedNetwork!.name, { exact: false }).first()).toBeVisible()

    await page.goto('/nodes/new')
    await page.getByLabel('Node name').fill(`live-e2e-${Date.now()}`)
    await page.getByRole('button', { name: 'Issue token' }).click()
    await expect(page).toHaveURL(/\/nodes\/new\/token$/)
    await expect(page.getByText(`sudo laneway node install ${controllerHost} --token-file ./laneway.code`, { exact: false })).toBeVisible()
    await page.reload()
    await expect(page.getByRole('heading', { name: 'Token unavailable' })).toBeVisible()

    await page.goto('/users/new')
    await page.getByLabel('Requested node name').fill(`live-e2e-user-${Date.now()}`)
    await page.getByLabel('Lease duration (hours)').fill('24')
    await page.getByRole('button', { name: 'Issue token' }).click()
    await expect(page).toHaveURL(/\/users\/new\/token$/)
    await expect(page.getByText(`laneway connect ${controllerHost} --ephemeral --token-file ./laneway.code`, { exact: false })).toBeVisible()

    await page.getByRole('button', { name: 'Sign out' }).click()
    await expect(page).toHaveURL(/\/sign-in$/)
    await expect(page.getByLabel('Signed in administrator')).toHaveCount(0)
  })
})
