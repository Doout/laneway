import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  // This suite exercises shared, persisted demo workflows in a single spec;
  // keep that file serial so route and credential mutations cannot race.
  fullyParallel: false,
  workers: 2,
  reporter: 'line',
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
