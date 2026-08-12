import { expect, test } from '@playwright/test'

const liveURL = process.env.LANEWAY_LIVE_E2E_URL
const adminToken = process.env.LANEWAY_LIVE_E2E_TOKEN
const controllerHost = liveURL ? new URL(liveURL).host : ''

test.describe('live controller console', () => {
  test.skip(!liveURL || !adminToken, 'Set LANEWAY_LIVE_E2E_URL and LANEWAY_LIVE_E2E_TOKEN to run against a controller.')

  test.use({ baseURL: liveURL, ignoreHTTPSErrors: true })

  test('authenticates, loads real inventory, and issues real one-time credentials', async ({ page }) => {
    await page.addInitScript(() => window.sessionStorage.setItem('laneway-console-operator', 'Legacy label'))
    await page.goto('/sign-in')
    await expect(page.getByLabel('Controller address')).toBeDisabled()
    await expect(page.getByRole('button', { name: 'SSO unavailable' })).toBeDisabled()
    await expect(page.getByLabel('Session label')).toHaveCount(0)
    expect(await page.evaluate(() => window.sessionStorage.getItem('laneway-console-operator'))).toBeNull()
    await page.getByLabel('Administrator token').fill(adminToken!)
    await page.getByRole('button', { name: 'Sign in' }).click()

    await expect(page).toHaveURL(/\/overview$/)
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()
    await expect(page.locator('.system-bar').getByText('Inventory loaded', { exact: true })).toBeVisible()
    await expect(page.getByRole('note', { name: 'Demo data notice' })).toHaveCount(0)
    const networksResponse = await page.request.get('/v1/admin/networks?limit=100', {
      headers: { Authorization: `Bearer ${adminToken}` },
    })
    expect(networksResponse.ok()).toBeTruthy()
    const networkResult = await networksResponse.json() as { networks: Array<{ name: string }> }
    expect(networkResult.networks.length).toBeGreaterThan(0)
    await expect(page.getByText(networkResult.networks[0].name, { exact: false }).first()).toBeVisible()

    await page.goto('/nodes/new')
    await expect(page.getByRole('button', { name: 'Connector' })).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Exit node' })).toBeDisabled()
    await page.getByLabel('Node name').fill(`live-e2e-${Date.now()}`)
    await page.getByRole('button', { name: 'Issue enrollment token' }).click()
    await expect(page).toHaveURL(/\/nodes\/new\/token$/)
    await expect(page.getByText('laneway node install', { exact: false })).toBeVisible()
    await expect(page.getByText('--token-file ./laneway.code', { exact: false })).toBeVisible()
    await page.reload()
    await expect(page.getByRole('heading', { name: 'Enrollment token unavailable' })).toBeVisible()

    await page.goto('/users/new')
    await expect(page.getByLabel('Network')).toBeDisabled()
    await page.getByLabel('Requested node name').fill(`live-e2e-user-${Date.now()}`)
    await page.getByLabel('Lease duration (hours)').fill('24')
    await page.getByRole('button', { name: 'Issue user token' }).click()
    await expect(page).toHaveURL(/\/users\/new\/token$/)
    await expect(page.getByText(`laneway connect ${controllerHost} --ephemeral --token-file ./laneway.code`, { exact: false })).toBeVisible()
    await page.reload()
    await expect(page.getByRole('heading', { name: 'User token unavailable' })).toBeVisible()

    await page.goto('/users/new')
    await page.getByRole('button', { name: /Remembered/ }).click()
    await page.getByLabel('Requested node name').fill(`live-e2e-remembered-${Date.now()}`)
    await expect(page.getByLabel('Lease duration (hours)')).toBeDisabled()
    await page.getByRole('button', { name: 'Issue user token' }).click()
    await expect(page).toHaveURL(/\/users\/new\/token$/)
    await expect(page.getByText(`laneway login ${controllerHost} --token-file ./laneway.code`, { exact: false })).toBeVisible()
    await page.reload()
    await expect(page.getByRole('heading', { name: 'User token unavailable' })).toBeVisible()

    await page.getByRole('button', { name: 'Sign out' }).click()
    await expect(page).toHaveURL(/\/sign-in$/)
    await expect(page.getByLabel('Session label')).toHaveCount(0)
    expect(await page.evaluate(() => window.sessionStorage.getItem('laneway-console-operator'))).toBeNull()
  })
})
