import type { DaemonStatus, DesktopSnapshot } from './contract'

export type ConnectionPresentation = {
  label: 'Connected' | 'Needs attention' | 'Disconnected'
  tone: 'good' | 'warning' | 'muted'
  detail: string
}

export function connectionPresentation(status: DaemonStatus): ConnectionPresentation {
  if (!status.running) {
    return { label: 'Disconnected', tone: 'muted', detail: 'The local daemon is not connected.' }
  }
  if (status.controller.configuration_lease_expired) {
    return { label: 'Needs attention', tone: 'warning', detail: 'The configuration lease expired.' }
  }
  if (status.controller.certificate_renewal_needed) {
    return { label: 'Needs attention', tone: 'warning', detail: 'The device certificate needs renewal.' }
  }
  return { label: 'Connected', tone: 'good', detail: status.selected_path || 'Secure path active' }
}

export function fallbackLabel(selectedPath: string): string {
  const normalized = selectedPath.toLowerCase()
  if (normalized.includes('tcp')) return 'TCP fallback'
  if (normalized.includes('direct')) return 'Direct'
  if (normalized.includes('relay')) return 'Relay'
  return selectedPath || 'Unavailable'
}

export function expiryLabel(unixSeconds: number, now = Date.now()): string {
  if (unixSeconds === 0) return 'Not reported'
  const milliseconds = unixSeconds * 1000
  if (milliseconds <= now) return 'Expired'
  const remainingMinutes = Math.floor((milliseconds - now) / 60_000)
  if (remainingMinutes < 60) return `${remainingMinutes}m remaining`
  const remainingHours = Math.floor(remainingMinutes / 60)
  if (remainingHours < 48) return `${remainingHours}h remaining`
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(milliseconds)
}

export function validateSnapshot(value: DesktopSnapshot): DesktopSnapshot {
  if (value.contract_version !== 1) {
    throw new Error(`Desktop contract ${value.contract_version} is not supported by this client.`)
  }
  return value
}

export function readableError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error)
  if (/permission denied|protected same-user|untrusted socket/i.test(message)) {
    return 'The local daemon belongs to another account. System-daemon access is not enabled for this client.'
  }
  if (/not found|no such file|cannot find/i.test(message)) {
    return 'The local daemon is not running.'
  }
  return message || 'The local daemon could not be reached.'
}

export function failedRefresh(error: unknown): { snapshot: undefined; error: string } {
  return { snapshot: undefined, error: readableError(error) }
}
