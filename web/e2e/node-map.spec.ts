import { expect, test } from '@playwright/test'

test('offline map, manual override, and responsive layout', async ({ page }) => {
  test.skip(process.env.LANEWAY_EXPECTED_BUILD_MODE === 'demo', 'Node map uses the live controller API.')
  const networkId = '3'.repeat(32)
  const sessionId = '2'.repeat(32)
  const now = Math.floor(Date.now() / 1000)
  const nodes = ['Toronto gateway', 'London worker', 'Private lab'].map((name, index) => ({ node_id: String(index + 4).repeat(32), network_id: networkId, name, enrollment_class: 'durable', enabled_capabilities: 0, created_at_unix_seconds: now }))
  let manual = false
  const external: string[] = []
  page.on('request', (request) => { if (!request.url().startsWith('http://127.0.0.1:4173')) external.push(request.url()) })
  await page.route('**/v1/admin/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    const headers = { 'X-Laneway-Session-ID': sessionId, 'X-Laneway-Session-Idle-Expires-At': String(now + 1800), 'X-Laneway-Session-Absolute-Expires-At': String(now + 3600) }
    let body: unknown
    if (path.endsWith('/auth/session')) body = { principal_id: '1'.repeat(32), username: 'owner', role: 'owner', permissions: ['network.list', 'network.read', 'node.read', 'node.manage', 'route.read'], all_networks: true, network_ids: [], session_id: sessionId, idle_lifetime_seconds: 1800, idle_expires_at_unix_seconds: now + 1800, absolute_expires_at_unix_seconds: now + 3600, csrf_token: 'c'.repeat(43) }
    else if (path.endsWith('/networks')) body = { networks: [{ network_id: networkId, name: 'Production', ipv4_pool: '100.96.0.0/16', configuration_epoch: 1, created_at_unix_seconds: now }] }
    else if (path.endsWith('/node-locations')) body = { automatic_enabled: true, location_provider: 'db-ip', node_locations: [
      { node_id: nodes[0].node_id, source: manual ? 'manual' : 'ip', stale: false, observed_at_unix_seconds: now, location: { label: manual ? 'Toronto office' : 'Toronto, CA', latitude: 43.65, longitude: -79.38, accuracy_km: manual ? 0 : 50 } },
      { node_id: nodes[1].node_id, source: 'ip', stale: true, observed_at_unix_seconds: now - 86400, location: { label: 'London, GB', latitude: 51.5, longitude: -0.1, accuracy_km: 100 } },
      { node_id: nodes[2].node_id, source: 'unknown', stale: false, observed_at_unix_seconds: now },
    ] }
    else if (path.endsWith('/nodes')) body = { nodes }
    else if (path.endsWith('/routes')) body = { routes: [{ route_id: '8'.repeat(32), network_id: networkId, node_id: nodes[0].node_id, prefix: '0.0.0.0/0', kind: 'exit', mode: 'nat', metric: 100, state: 'approved', created_at_unix_seconds: now }] }
    else if (path.endsWith('/location')) {
      expect(route.request().headers()['x-laneway-csrf']).toBe('c'.repeat(43))
      manual = route.request().method() === 'PUT'
      return route.fulfill({ status: 204, headers })
    } else if (path.endsWith(networkId)) body = { network_id: networkId, name: 'Production', ipv4_pool: '100.96.0.0/16', configuration_epoch: 1, created_at_unix_seconds: now }
    else throw new Error(`Unexpected map request ${path}`)
    await route.fulfill({ status: 200, contentType: 'application/json', headers, body: JSON.stringify(body) })
  })
  await page.goto('/networks?view=map')
  await expect(page.getByText('2 located · 1 unknown')).toBeVisible()
  await expect(page.getByRole('link', { name: 'IP geolocation by DB-IP' })).toHaveAttribute('href', 'https://db-ip.com')
  await page.getByRole('button', { name: /Toronto gateway/ }).click()
  await expect(page.getByText('Network exit', { exact: true })).toBeVisible()
  await page.getByLabel('Site name').fill('Toronto office')
  await page.getByRole('button', { name: 'Save location' }).click()
  await expect(page.getByText('Manual location', { exact: true })).toBeVisible()
  await expect(page.getByLabel('Site name')).toHaveValue('Toronto office')
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: '/tmp/laneway-node-map-desktop.png', fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.getByRole('button', { name: 'Use automatic' })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: '/tmp/laneway-node-map-mobile.png', fullPage: true })
  await page.getByRole('button', { name: 'Use automatic' }).click()
  await expect(page.getByText('Approximate IP location · ±50 km')).toBeVisible()
  await page.setViewportSize({ width: 1280, height: 800 })
  await page.getByRole('button', { name: 'Use dark theme' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: '/tmp/laneway-node-map-dark.png', fullPage: true })
  expect(external).toEqual([])
})
