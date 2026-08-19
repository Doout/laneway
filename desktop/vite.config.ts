import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vitest/config'

const repositoryRoot = fileURLToPath(new URL('..', import.meta.url))

export default defineConfig({
  build: {
    sourcemap: false,
    target: 'es2022',
  },
  clearScreen: false,
  server: {
    fs: { allow: [repositoryRoot] },
    host: '127.0.0.1',
    port: 4176,
    strictPort: true,
    watch: { ignored: ['**/src-tauri/**'] },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
