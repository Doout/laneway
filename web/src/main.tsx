import '@fontsource-variable/manrope'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import { App } from './App'
import { ControlPlaneProvider } from './lib/control-plane'
import { purgeLegacyAuthStorage } from './lib/legacy-auth-storage'
import './styles.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 30_000, retry: 1 },
  },
})

purgeLegacyAuthStorage()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
    <BrowserRouter>
      <ControlPlaneProvider>
        <App />
      </ControlPlaneProvider>
    </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
