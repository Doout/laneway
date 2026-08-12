import { expect, test } from 'vitest'
import { isCanonicalIpPrefix } from './ip-prefix'

test('accepts canonical IPv4 and IPv6 prefixes', () => {
  expect(isCanonicalIpPrefix('10.24.0.0/16')).toBe(true)
  expect(isCanonicalIpPrefix('2001:db8:1::/64')).toBe(true)
  expect(isCanonicalIpPrefix('0.0.0.0/0')).toBe(true)
})

test('rejects host bits and noncanonical IPv4 input', () => {
  expect(isCanonicalIpPrefix('10.24.1.1/16')).toBe(false)
  expect(isCanonicalIpPrefix('2001:db8:1::1/64')).toBe(false)
  expect(isCanonicalIpPrefix('010.24.0.0/16')).toBe(false)
  expect(isCanonicalIpPrefix('2001:0db8:1::/64')).toBe(false)
  expect(isCanonicalIpPrefix('2001:DB8:1::/64')).toBe(false)
  expect(isCanonicalIpPrefix('2001:db8:0:0::/64')).toBe(false)
})

test('supports network-pool constraints', () => {
  const options = { family: 'ipv4' as const, minBits: 8, maxBits: 30 }
  expect(isCanonicalIpPrefix('100.88.3.0/24', options)).toBe(true)
  expect(isCanonicalIpPrefix('100.88.3.1/24', options)).toBe(false)
  expect(isCanonicalIpPrefix('100.88.3.0/31', options)).toBe(false)
})
