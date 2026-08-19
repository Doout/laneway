import type { DesktopApi, DesktopSnapshot, Peer, Route } from './contract'
import { connectionPresentation, expiryLabel, failedRefresh, fallbackLabel, validateSnapshot } from './presentation'

const escapeHtml = (value: string | number) => String(value)
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#039;')

const shortIdentity = (value: string) => value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-5)}` : value

const peerLabel = (peer: Peer) => peer.name || shortIdentity(peer.node_id)

const routeRow = (route: Route) => `
  <li class="route-row">
    <span class="route-icon" aria-hidden="true">↗</span>
    <span><strong>${escapeHtml(route.prefix)}</strong><small>${escapeHtml(route.kind)}</small></span>
    <code>${escapeHtml(shortIdentity(route.via_node))}</code>
  </li>`

export class LanewayDesktop {
  private snapshot?: DesktopSnapshot
  private busy = false
  private error = ''

  constructor(private readonly root: HTMLElement, private readonly api: DesktopApi) {}

  start() {
    this.render()
    void this.refresh()
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && !this.busy) void this.refresh(true)
    })
  }

  private async refresh(quiet = false) {
    if (this.busy) return
    this.busy = true
    if (!quiet || !this.snapshot) this.error = ''
    this.render()
    try {
      this.snapshot = validateSnapshot(await this.api.snapshot())
      this.error = ''
    } catch (error) {
      const failure = failedRefresh(error)
      this.snapshot = failure.snapshot
      this.error = failure.error
    } finally {
      this.busy = false
      this.render()
    }
  }

  private bind() {
    this.root.querySelector<HTMLButtonElement>('#refresh')?.addEventListener('click', () => void this.refresh())
  }

  private render() {
    this.root.innerHTML = this.snapshot ? this.renderSnapshot(this.snapshot) : this.renderUnavailable()
    this.bind()
  }

  private shell(content: string, status = 'Local daemon') {
    return `
      <div class="desktop-shell">
        <header class="titlebar">
          <div class="wordmark">
            <span class="brand-mark" aria-hidden="true"><i></i><i></i><i></i></span>
            <strong>Laneway</strong>
          </div>
          <span class="titlebar-context">${escapeHtml(status)}</span>
        </header>
        ${content}
      </div>`
  }

  private renderUnavailable() {
    const message = this.error || 'Looking for the local daemon…'
    return this.shell(`
      <main class="centered-state">
        <div class="connection-orb connection-orb--muted" aria-hidden="true"></div>
        <p class="eyebrow">Local connection</p>
        <h1>${this.busy ? 'Connecting' : 'Daemon unavailable'}</h1>
        <p>${escapeHtml(message)}</p>
        <button class="button button--primary" id="refresh" type="button" ${this.busy ? 'disabled' : ''}>Try again</button>
        <p class="boundary-note">Laneway only connects to a protected daemon owned by your account.</p>
      </main>`)
  }

  private renderSnapshot(snapshot: DesktopSnapshot) {
    const { status, peers, routes } = snapshot
    const connection = connectionPresentation(status)
    const allRoutes = routes.length > 0 ? routes : status.selected_routes.map((prefix) => ({ prefix, via_node: '', kind: 'private' }))
    const exitAvailable = snapshot.capabilities.exit_selection
    const selectedExit = status.exit.enabled ? status.exit.selected_node_id || '' : ''
    const selectedExitPeer = peers.find((peer) => peer.node_id === selectedExit)
    const exitSummary = !exitAvailable
      ? 'Exit controls require an authoritative daemon capability and candidate list.'
      : status.exit.enabled
      ? status.exit.authorized ? 'Authorized exit active' : 'Exit requested; waiting for authorization'
      : 'Private routes only'
    const error = this.error ? `<div class="inline-alert" role="alert">${escapeHtml(this.error)}</div>` : ''

    return this.shell(`
      <main class="workspace">
        <section class="connection-header">
          <div class="connection-copy">
            <div class="connection-state connection-state--${connection.tone}">
              <span class="connection-orb" aria-hidden="true"></span>${connection.label}
            </div>
            <h1>${escapeHtml(status.name || 'This device')}</h1>
            <p>${escapeHtml(connection.detail)}</p>
          </div>
          <button class="icon-button" id="refresh" type="button" aria-label="Refresh local status" title="Refresh" ${this.busy ? 'disabled' : ''}>↻</button>
        </section>
        ${error}

        <section class="summary-grid" aria-label="Connection summary">
          <div><span>Network</span><strong title="${escapeHtml(status.network_id)}">${escapeHtml(shortIdentity(status.network_id))}</strong></div>
          <div><span>Address</span><strong>${escapeHtml(status.overlay_addresses[0] || 'Not assigned')}</strong></div>
          <div><span>Path</span><strong>${escapeHtml(fallbackLabel(status.selected_path))}</strong></div>
          <div><span>Identity lease</span><strong>${escapeHtml(expiryLabel(status.controller.identity_lease_expires_at_unix_seconds))}</strong></div>
        </section>

        <div class="content-grid">
          <section class="panel routes-panel">
            <header class="panel-heading">
              <div><p class="eyebrow">Reachable now</p><h2>Private routes</h2></div>
              <span>${allRoutes.length}</span>
            </header>
            ${allRoutes.length > 0
              ? `<ul class="route-list">${allRoutes.map(routeRow).join('')}</ul>`
              : '<div class="empty-row">No private routes are active.</div>'}
          </section>

          <aside class="panel session-panel">
            <div class="panel-heading"><div><p class="eyebrow">Routing mode</p><h2>Exit</h2></div></div>
            <p>${escapeHtml(exitSummary)}</p>
            <div class="exit-readout">
              <span>Current exit</span>
              <strong>${selectedExitPeer ? escapeHtml(peerLabel(selectedExitPeer)) : selectedExit ? escapeHtml(shortIdentity(selectedExit)) : 'None'}</strong>
            </div>
            <dl class="session-facts">
              <div><dt>Interface</dt><dd>${escapeHtml(status.interface || 'Not active')}</dd></div>
              <div><dt>Relay</dt><dd title="${escapeHtml(status.relay)}">${escapeHtml(status.relay || 'Not active')}</dd></div>
              <div><dt>Certificate</dt><dd>${escapeHtml(expiryLabel(status.controller.certificate_not_after_unix_seconds))}</dd></div>
              <div><dt>Version</dt><dd>${escapeHtml(status.product_version || 'Unknown')}</dd></div>
            </dl>
            <div class="capability-summary" aria-label="Desktop capabilities">
              <span><i class="capability-dot capability-dot--ready"></i>Status and private routes</span>
              <span><i class="capability-dot ${exitAvailable ? 'capability-dot--ready' : ''}"></i>${exitAvailable ? 'Exit control available' : 'Exit control not available'}</span>
              <span><i class="capability-dot ${snapshot.capabilities.snapshot_coherence ? 'capability-dot--ready' : ''}"></i>${snapshot.capabilities.snapshot_coherence ? 'Restart-safe snapshot' : 'Legacy snapshot; restart detection unavailable'}</span>
              <span><i class="capability-dot"></i>${snapshot.capabilities.connection_control ? 'Connection control available' : 'Connect and profiles not available'}</span>
            </div>
          </aside>
        </div>
      </main>
      <footer class="statusbar">
        <span>Same-user daemon</span>
        <span>Contract v${snapshot.contract_version}</span>
        <span>${escapeHtml(snapshot.platform)}</span>
      </footer>`, status.network_id ? 'Endpoint connection' : 'Local daemon')
  }
}
