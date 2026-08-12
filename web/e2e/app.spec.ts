import { expect, test } from '@playwright/test'
import { approvedScreens } from './approved-screens'

for (const [path, heading] of approvedScreens) {
  test(`${path} renders its approved screen`, async ({ page }) => {
    const pageErrors: string[] = []
    page.on('pageerror', error => pageErrors.push(error.message))
    await page.goto(path)
    await expect(page.getByRole('heading', { name: heading }).first()).toBeVisible()
    expect(pageErrors).toEqual([])
  })
}

test('sign-in, enrollment, route approval, and rule creation flow end to end', async ({ page }) => {
  const navigateInApp = async (path: string) => {
    await page.evaluate(nextPath => {
      window.history.pushState({}, '', nextPath)
      window.dispatchEvent(new PopStateEvent('popstate'))
    }, path)
    await expect(page).toHaveURL(new RegExp(`${path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`))
  }
  await page.goto('/sign-in')
  await expect(page.getByLabel('Session label')).toHaveCount(0)
  await page.getByLabel('Administrator token').fill('demo-administrator-token')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/overview$/)
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()

  await navigateInApp('/nodes/new')
  await page.getByLabel('Node name').fill('field-relay-01')
  await page.getByRole('button', { name: 'Issue enrollment token' }).click()
  await expect(page).toHaveURL(/\/nodes\/new\/token$/)
  await expect(page.getByText('laneway node install controller.example.com --token-file ./laneway.code', { exact: false })).toBeVisible()

  await navigateInApp('/users/new')
  await page.getByLabel('Requested node name').fill('Incident responder')
  await page.getByRole('button', { name: 'Issue user token' }).click()
  await expect(page).toHaveURL(/\/users\/new\/token$/)
  await expect(page.getByText('Copy this credential now.')).toBeVisible()

  await navigateInApp('/routes/new')
  await page.getByLabel('Route name').fill('Finance services')
  await page.getByText('I understand this advertisement changes').click()
  await page.getByRole('button', { name: 'Continue to approval' }).click()
  await expect(page).toHaveURL(/\/routes\/rte_preview\/approve$/)
  await page.getByText('I verified the destination').click()
  await page.getByLabel('Type 10.24.0.0/16 to confirm').fill('10.24.0.0/16')
  await page.getByRole('button', { name: 'Approve route' }).click()
  await expect(page.getByRole('heading', { name: 'Route approved' })).toBeVisible()

  await navigateInApp('/access/new')
  await page.getByLabel('Description').fill('Allow finance operators')
  await page.getByText('I reviewed the selector and priority.').click()
  await page.getByRole('button', { name: 'Create rule' }).click()
  await expect(page).toHaveURL(/\/access\/acl_preview$/)
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
})

test('pending-route links apply the query filter and primary navigation works from the keyboard', async ({ page }) => {
  await page.goto('/routes?state=pending')
  await expect(page.getByRole('button', { name: 'Needs attention' })).toHaveClass(/is-active/)
  await expect(page.locator('tbody tr')).toHaveCount(1)
  await expect(page.getByRole('table').getByText('Kubernetes API')).toBeVisible()

  await page.getByRole('link', { name: 'Overview' }).first().focus()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(/\/overview$/)
})

const missingEntities = [
  ['/nodes/missing', 'Node not found'],
  ['/users/missing', 'User enrollment not found'],
  ['/routes/missing', 'Route not found'],
  ['/access/missing', 'Access rule not found'],
  ['/infrastructure/networks/missing', 'Network not found'],
  ['/infrastructure/relays/missing', 'Relay not found'],
] as const

for (const [path, heading] of missingEntities) {
  test(`${path} fails explicitly instead of showing a fallback record`, async ({ page }) => {
    await page.goto(path)
    await expect(page.getByRole('heading', { name: heading })).toBeVisible()
  })
}

test('route approval persists in detail and inventory while withdrawal supports cancellation', async ({ page }) => {
  await page.goto('/routes/rte_01J8KUBEAPI/approve')
  await page.getByText('I verified the destination').click()
  await page.getByLabel('Type 10.24.8.10/32 to confirm').fill('10.24.8.10/32')
  await page.getByRole('button', { name: 'Approve route' }).click()
  await page.getByRole('button', { name: 'View route' }).click()
  await expect(page.getByText('Route approved for distribution', { exact: false })).toBeVisible()

  await page.getByRole('button', { name: 'Withdraw route' }).click()
  await expect(page.getByLabel('Type 10.24.8.10/32 to confirm')).toBeVisible()
  await page.getByRole('button', { name: 'Cancel' }).last().click()
  await expect(page.getByLabel('Type 10.24.8.10/32 to confirm')).toHaveCount(0)

  await page.getByRole('link', { name: 'All routes' }).last().click()
  const row = page.getByRole('row').filter({ hasText: 'Kubernetes API' })
  await expect(row.getByText('Healthy')).toBeVisible()
})

test('node capability changes persist after returning through inventory', async ({ page }) => {
  await page.goto('/nodes/atlas-gateway/capabilities')
  await page.getByText('Publish subnet routes').click()
  await page.getByLabel('Type SAVE atlas-gateway to confirm').fill('SAVE atlas-gateway')
  await page.getByRole('button', { name: 'Save capabilities' }).click()
  await expect(page.getByText('publish disabled', { exact: false })).toBeVisible()
  await page.getByRole('link', { name: 'Back to nodes' }).click()
  const row = page.getByRole('row').filter({ hasText: 'atlas-gateway' })
  await row.getByRole('link', { name: 'View' }).click()
  await expect(page.getByText('publish disabled', { exact: false })).toBeVisible()
})

test('access-rule disable supports cancellation and persists to inventory', async ({ page }) => {
  await page.goto('/access/acl_01J8PRODOPS')
  await page.getByRole('button', { name: 'Disable rule' }).click()
  await page.getByRole('button', { name: 'Cancel' }).last().click()
  await expect(page.getByRole('button', { name: 'Disable rule' })).toBeVisible()

  await page.getByRole('button', { name: 'Disable rule' }).click()
  await page.getByLabel('Type Production operators to confirm').fill('Production operators')
  await page.getByRole('button', { name: 'Disable rule' }).last().click()
  await expect(page.getByText('Access rule disabled', { exact: false })).toBeVisible()
  await page.getByRole('link', { name: 'All rules' }).click()
  const row = page.getByRole('row').filter({ hasText: 'Production operators' })
  await expect(row.getByText('Disabled')).toBeVisible()
})

test('relay registration confirmation can be canceled and the confirmed relay persists', async ({ page }) => {
  await page.goto('/infrastructure/relays/new')
  await page.getByLabel('Relay name').fill('lhr-relay-01')
  await page.getByRole('button', { name: 'Review registration' }).click()
  await page.getByRole('button', { name: 'Cancel' }).last().click()
  await expect(page.getByLabel('Relay name')).toHaveValue('lhr-relay-01')

  await page.getByRole('button', { name: 'Review registration' }).click()
  await page.getByLabel('Type “lhr-relay-01” to confirm').fill('lhr-relay-01')
  await page.getByRole('button', { name: 'Generate credential' }).click()
  await expect(page.getByText('lhr-relay-01 registered', { exact: false })).toBeVisible()
  await page.getByRole('link', { name: 'Open relay' }).click()
  await expect(page.getByRole('heading', { level: 2, name: 'lhr-relay-01' })).toBeVisible()
  await page.getByRole('link', { name: 'Infrastructure', exact: true }).first().click()
  await expect(page.getByLabel('Relay inventory').getByText('lhr-relay-01')).toBeVisible()
})
