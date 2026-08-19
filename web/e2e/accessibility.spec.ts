import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'
import { approvedScreens } from './approved-screens'

const wcagTags = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa']

function formatViolations(violations: Awaited<ReturnType<AxeBuilder['analyze']>>['violations']) {
  return violations.map((violation) => ({
    id: violation.id,
    impact: violation.impact,
    targets: violation.nodes.map((node) => node.target),
  }))
}

async function expectNoHorizontalPageOverflow(page: Page) {
  const widths = await page.evaluate(() => ({
    viewport: window.innerWidth,
    document: document.documentElement.scrollWidth,
  }))
  expect(widths.document).toBeLessThanOrEqual(widths.viewport)
}

for (const [path, heading] of approvedScreens) {
  test(`${path} meets WCAG A and AA automated checks`, async ({ page }) => {
    await page.goto(path)
    await expect(page.getByRole('heading', { name: heading }).first()).toBeVisible()

    const results = await new AxeBuilder({ page }).withTags(wcagTags).analyze()
    expect(results.violations, JSON.stringify(formatViolations(results.violations), null, 2)).toEqual([])
  })
}

test.describe('tablet navigation', () => {
  test.use({ viewport: { width: 768, height: 1024 } })

  test('collapsed navigation keeps accessible names and keyboard operation', async ({ page }) => {
    await page.goto('/routes')
    const navigation = page.getByRole('navigation', { name: 'Primary navigation' })
    const labels = ['Overview', 'Nodes', 'Users', 'Infrastructure', 'Access', 'Security', 'Audit']

    for (const label of labels) {
      await expect(navigation.getByRole('link', { name: label, exact: true })).toBeVisible()
    }
    await expect(navigation.getByRole('link', { name: /^Routes, \d+ routes need review$/ })).toBeVisible()

    await page.keyboard.press('Tab')
    await expect(page.getByRole('link', { name: 'Laneway overview' })).toBeFocused()
    await page.keyboard.press('Tab')
    await expect(navigation.getByRole('link', { name: 'Overview', exact: true })).toBeFocused()
    await page.keyboard.press('Enter')
    await expect(page).toHaveURL(/\/overview$/)
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()
    await expectNoHorizontalPageOverflow(page)
  })
})

test.describe('mobile layout', () => {
  test.use({ viewport: { width: 375, height: 812 } })

  test('inventory and bottom navigation remain inside the viewport', async ({ page }) => {
    await page.goto('/nodes')
    await expect(page.getByRole('heading', { name: '5 Nodes' })).toBeVisible()
    await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible()
    await expectNoHorizontalPageOverflow(page)

    const navigation = page.getByRole('navigation', { name: 'Primary navigation' })
    for (const label of ['Overview', 'Nodes', 'Users', 'Infrastructure', 'Access', 'Security', 'Audit']) {
      await expect(navigation.getByRole('link', { name: label, exact: true })).toBeVisible()
    }
    await expect(navigation.getByRole('link', { name: /^Routes, \d+ routes need review$/ })).toBeVisible()

    const linkBoxes = await navigation.getByRole('link').evaluateAll((links) => links.map((link) => {
      const box = link.getBoundingClientRect()
      return { left: box.left, right: box.right, top: box.top, bottom: box.bottom, width: box.width, height: box.height }
    }))
    for (const box of linkBoxes) {
      expect(box.left).toBeGreaterThanOrEqual(0)
      expect(box.right).toBeLessThanOrEqual(375)
      expect(box.top).toBeGreaterThanOrEqual(0)
      expect(box.bottom).toBeLessThanOrEqual(812)
      expect(box.width).toBeGreaterThanOrEqual(44)
      expect(box.height).toBeGreaterThanOrEqual(44)
    }
  })

  for (const [path, selector] of [
    ['/nodes/new/token', 'pre.nodes-command'],
    ['/users/new/token', 'pre.users-command'],
  ] as const) {
    test(`${path} exposes its scrollable command to the keyboard`, async ({ page }) => {
      await page.goto(path)
      const command = page.locator(selector)
      await expect(command).toHaveAttribute('tabindex', '0')
      expect(await command.evaluate((element) => element.scrollWidth > element.clientWidth)).toBe(true)
      await command.focus()
      await expect(command).toBeFocused()
      await expectNoHorizontalPageOverflow(page)
    })
  }
})

test('long node names remain contained on the node detail page', async ({ page }) => {
  const longName = 'ibmcloud-shared-exit-v0261-expired-exit-c4ae1eae8905a7d8707680cb27cc03ad'
  await page.goto('/nodes/new')
  await page.getByLabel('Node name').fill(longName)
  await page.getByRole('button', { name: 'Issue enrollment token' }).click()
  await page.getByRole('link', { name: 'View node', exact: true }).click()
  await expect(page.getByRole('heading', { name: longName, level: 2 })).toBeVisible()

  for (const width of [1280, 768, 375]) {
    await page.setViewportSize({ width, height: 900 })
    const overflow = await page.locator('.identity-block > h2, .metadata dd, .nodes-path, .nodes-path > span:not([aria-hidden]), .nodes-path .status').evaluateAll((elements) => elements.flatMap((element) => element.scrollWidth > element.clientWidth + 1
      ? [{ element: element.tagName.toLowerCase(), clientWidth: element.clientWidth, scrollWidth: element.scrollWidth }]
      : []))
    expect(overflow, `overflow at ${width}px`).toEqual([])
    await expectNoHorizontalPageOverflow(page)
  }
})

test('interactive topology groups preserve descendant link semantics', async ({ page }) => {
  await page.goto('/infrastructure')
  const topology = page.getByRole('group', { name: 'Network and relay topology' })
  const relay = topology.getByRole('link').first()
  await expect(relay).toBeVisible()
  await relay.focus()
  await expect(relay).toBeFocused()

  await page.goto('/infrastructure/networks/production')
  const path = page.getByRole('group', { name: /connected nodes use .* to reach .* routes with relay fallback/ })
  const gateway = path.getByRole('link').first()
  await expect(gateway).toBeVisible()
  await gateway.focus()
  await expect(gateway).toBeFocused()
})
