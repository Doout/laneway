type PrefixOptions = {
  family?: 'any' | 'ipv4'
  minBits?: number
  maxBits?: number
}

export function isCanonicalIpPrefix(value: string, options: PrefixOptions = {}) {
  if (value !== value.trim()) return false
  const parts = value.split('/')
  if (parts.length !== 2 || !/^(0|[1-9]\d*)$/.test(parts[1])) return false
  const bits = Number(parts[1])
  const bytes = parts[0].includes(':') ? parseIpv6(parts[0]) : parseIpv4(parts[0])
  if (!bytes || (options.family === 'ipv4' && bytes.length !== 4)) return false
  const canonicalAddress = bytes.length === 4 ? bytes.join('.') : formatIpv6(bytes)
  if (parts[0] !== canonicalAddress) return false
  const addressBits = bytes.length * 8
  if (bits < (options.minBits ?? 0) || bits > (options.maxBits ?? addressBits) || bits > addressBits) return false
  const wholeBytes = Math.floor(bits / 8)
  const remainingBits = bits % 8
  if (remainingBits && (bytes[wholeBytes] & ((1 << (8 - remainingBits)) - 1)) !== 0) return false
  return bytes.slice(wholeBytes + (remainingBits ? 1 : 0)).every(byte => byte === 0)
}

function parseIpv4(value: string) {
  const octets = value.split('.')
  if (octets.length !== 4 || octets.some(octet => !/^(0|[1-9]\d{0,2})$/.test(octet) || Number(octet) > 255)) return null
  return octets.map(Number)
}

function parseIpv6(value: string) {
  if (!value || value.includes('%') || value.includes('.')) return null
  const halves = value.split('::')
  if (halves.length > 2) return null
  const left = halves[0] ? halves[0].split(':') : []
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const validGroup = (group: string) => /^[0-9a-f]{1,4}$/i.test(group)
  if (![...left, ...right].every(validGroup)) return null
  if (halves.length === 1 && left.length !== 8) return null
  if (halves.length === 2 && left.length + right.length >= 8) return null
  const groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
  return groups.flatMap(group => {
    const parsed = Number.parseInt(group, 16)
    return [parsed >> 8, parsed & 0xff]
  })
}

function formatIpv6(bytes: number[]) {
  const groups = Array.from({ length: 8 }, (_, index) => ((bytes[index * 2] << 8) | bytes[index * 2 + 1]).toString(16))
  let bestStart = -1
  let bestLength = 0
  for (let index = 0; index < groups.length;) {
    if (groups[index] !== '0') {
      index += 1
      continue
    }
    let end = index + 1
    while (end < groups.length && groups[end] === '0') end += 1
    if (end - index >= 2 && end - index > bestLength) {
      bestStart = index
      bestLength = end - index
    }
    index = end
  }
  if (bestStart < 0) return groups.join(':')
  return `${groups.slice(0, bestStart).join(':')}::${groups.slice(bestStart + bestLength).join(':')}`
}
