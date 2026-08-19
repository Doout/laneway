export const desktopContractVersion = 1 as const

export type ControllerHealth = {
  candidate_exchange_enabled: boolean
  certificate_presented_serial: string
  certificate_renewal_needed: boolean
  certificate_renew_after_unix_seconds: number
  certificate_not_after_unix_seconds: number
  identity_lease_expires_at_unix_seconds: number
  configuration_lease_valid_until_unix_seconds: number
  configuration_lease_expired: boolean
}

export type ExitStatus = {
  enabled: boolean
  selected_node_id?: string
  authorized: boolean
  serving: boolean
  forwarding_ready: boolean
  nat_ready: boolean
  forwarded_packets: number
  namespace_cleanup_failures: number
}

export type DaemonStatus = {
  daemon_instance_id: string
  api_revision: number
  running: boolean
  actor: string
  product_version: string
  control_version: string
  packet_version: number
  capabilities: string
  selected_path: string
  network_id: string
  node_id: string
  name: string
  overlay_addresses: string[]
  selected_routes: string[]
  interface: string
  relay: string
  mtu: number
  exit: ExitStatus
  controller: ControllerHealth
}

export type Peer = {
  node_id: string
  name?: string
  prefixes: string[]
  path: string
}

export type Route = {
  prefix: string
  via_node: string
  kind: string
}

export type DesktopSnapshot = {
  contract_version: typeof desktopContractVersion
  platform: 'linux' | 'macos'
  ownership: 'same-user-daemon'
  capabilities: DesktopCapabilities
  status: DaemonStatus
  peers: Peer[]
  routes: Route[]
}

export type DesktopCapabilities = {
  status: boolean
  private_routes: boolean
  snapshot_coherence: boolean
  exit_selection: boolean
  profile_management: boolean
  connection_control: boolean
  ephemeral_sessions: boolean
  updates: boolean
  diagnostics: boolean
}

export interface DesktopApi {
  snapshot(): Promise<DesktopSnapshot>
}
