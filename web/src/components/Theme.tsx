import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { Moon, Sun } from 'lucide-react'
import clsx from 'clsx'

type Theme = 'light' | 'dark'

const ThemeContext = createContext<{ theme: Theme; setTheme: (theme: Theme) => void } | null>(null)

function initialTheme(): Theme {
  if (typeof window === 'undefined') return 'light'
  try {
    const stored = window.localStorage.getItem('laneway-console-theme')
    if (stored === 'light' || stored === 'dark') return stored
  } catch {
    // Storage can be unavailable in hardened or test browser contexts.
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(initialTheme)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.style.colorScheme = theme
    try { window.localStorage.setItem('laneway-console-theme', theme) } catch { /* Storage is optional. */ }
  }, [theme])

  return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>
}

export function ThemeToggle({ className }: { className?: string }) {
  const value = useContext(ThemeContext)
  if (!value) return null
  const next = value.theme === 'dark' ? 'light' : 'dark'
  const Icon = value.theme === 'dark' ? Sun : Moon
  return <button className={clsx('theme-toggle', className)} type="button" aria-label={`Use ${next} theme`} title={`Use ${next} theme`} onClick={() => value.setTheme(next)}><Icon aria-hidden="true" size={16} /></button>
}
