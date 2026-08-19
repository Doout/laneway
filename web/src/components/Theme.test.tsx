import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { ThemeProvider, ThemeToggle } from './Theme'

describe('theme controls', () => {
  afterEach(() => {
    cleanup()
    window.localStorage.clear()
    delete document.documentElement.dataset.theme
    document.documentElement.style.colorScheme = ''
  })

  it('switches theme, updates the document, and persists the choice', async () => {
    render(<ThemeProvider><ThemeToggle /></ThemeProvider>)

    const toggle = await screen.findByRole('button', { name: 'Use dark theme' })
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe('light'))

    fireEvent.click(toggle)

    await waitFor(() => expect(document.documentElement.dataset.theme).toBe('dark'))
    expect(document.documentElement.style.colorScheme).toBe('dark')
    expect(window.localStorage.getItem('laneway-console-theme')).toBe('dark')
    expect(screen.getByRole('button', { name: 'Use light theme' })).toBeVisible()
  })
})
