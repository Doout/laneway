const LEGACY_AUTH_STORAGE_KEY_PARTS = [
  ['laneway', 'console', 'admin', 'token'],
  ['laneway', 'console', 'operator'],
] as const

export function purgeLegacyAuthStorage() {
  if (typeof window === 'undefined') return
  for (const storage of [window.localStorage, window.sessionStorage]) {
    for (const parts of LEGACY_AUTH_STORAGE_KEY_PARTS) storage.removeItem(parts.join('-'))
  }
}
