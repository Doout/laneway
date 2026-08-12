import { defineConfig, devices } from '@playwright/test'

const runsLiveController = Boolean(process.env.LANEWAY_LIVE_E2E_URL)

export default defineConfig({
  testDir: './e2e',
  // This suite exercises shared, persisted demo workflows in a single spec;
  // keep that file serial so route and credential mutations cannot race.
  fullyParallel: false,
  workers: 2,
  reporter: 'line',
  // A live-controller failure can include real credentials or one-time secrets
  // in Playwright's automatic error-context output even with recordings off.
  preserveOutput: runsLiveController ? 'never' : 'failures-only',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'corepack pnpm preview --host 127.0.0.1',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: false,
  },
})
