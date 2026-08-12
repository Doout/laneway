import { configDefaults, defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig(({ command, mode }) => {
  if (command === 'build' && mode !== 'live' && mode !== 'demo') {
    throw new Error('Choose the explicit build:live or build:demo script; an unscoped console build is not allowed.')
  }

  return {
    plugins: [{
      name: 'laneway-mode-app',
      enforce: 'pre',
      resolveId(source, importer) {
        if (source === './App' && importer?.endsWith('/src/main.tsx')) {
          return new URL(mode === 'live' ? './src/App.live.tsx' : './src/App.tsx', import.meta.url).pathname
        }
      },
    }, react()],
    test: {
      environment: 'jsdom',
      setupFiles: './src/test/setup.ts',
      css: true,
      exclude: [...configDefaults.exclude, 'e2e/**'],
      env: { MODE: 'demo' },
    },
    server: {
      port: 4173,
      strictPort: true,
    },
    build: {
      sourcemap: mode === 'demo',
    },
  }
})
