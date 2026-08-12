import { describe, expect, it } from 'vitest'
import { parseConsoleBuildMode } from './control-plane'

describe('console build mode', () => {
  it.each(['live', 'demo'] as const)('accepts the explicit %s mode', (mode) => {
    expect(parseConsoleBuildMode(mode)).toBe(mode)
  })

  it.each(['production', '', undefined])('rejects the unsupported %s mode', (mode) => {
    expect(() => parseConsoleBuildMode(mode)).toThrow('Unsupported console build mode')
  })
})
