import { describe, expect, it } from 'vitest'
import { durableNodeEnrollmentCommand, userEnrollmentCommand } from './enrollment-commands'

describe('console enrollment commands', () => {
  const controllerHost = 'controller.example.test:9443'

  it('matches the durable Linux node install surface', () => {
    expect(durableNodeEnrollmentCommand(controllerHost)).toBe(
      'sudo laneway node install controller.example.test:9443 --token-file ./laneway.code',
    )
  })

  it('matches the remembered user login surface', () => {
    expect(userEnrollmentCommand(controllerHost, 'Remembered')).toBe(
      'laneway login controller.example.test:9443 --token-file ./laneway.code',
    )
  })

  it('matches the ephemeral user connection surface', () => {
    expect(userEnrollmentCommand(controllerHost, 'Ephemeral')).toBe(
      'laneway connect controller.example.test:9443 --ephemeral --token-file ./laneway.code',
    )
  })

  it.each(['', 'controller.example.test 9443'])('rejects an unsafe controller host %j', (host) => {
    expect(() => durableNodeEnrollmentCommand(host)).toThrow('Controller host')
  })
})
