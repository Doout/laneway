import { describe, expect, it } from 'vitest'
import { safeReturnPath } from './safe-navigation'

describe('safeReturnPath', () => {
  it('preserves a same-origin deep link', () => {
    expect(safeReturnPath('/routes?state=pending#queue')).toBe('/routes?state=pending#queue')
  })

  it.each([
    'https://attacker.invalid/path',
    '//attacker.invalid/path',
    '/\\attacker.invalid/path',
    '/sign-in',
    '/setup',
    undefined,
  ])('rejects an unsafe return destination %#', (value) => {
    expect(safeReturnPath(value)).toBe('/overview')
  })
})
