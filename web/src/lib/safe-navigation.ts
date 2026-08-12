export function safeReturnPath(value: unknown, fallback = '/overview') {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return fallback
  try {
    const target = new URL(value, window.location.origin)
    if (target.origin !== window.location.origin || target.pathname === '/sign-in' || target.pathname === '/setup') return fallback
    return `${target.pathname}${target.search}${target.hash}`
  } catch {
    return fallback
  }
}
