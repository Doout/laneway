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
    <span><strong>${escapeHtml(route.prefix)}</strong><small>${escapeHtml(route.kind)}</small></span>
    ${route.via_node ? `<code title="${escapeHtml(route.via_node)}">${escapeHtml(shortIdentity(route.via_node))}</code>` : ''}
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
    const refreshFocused = document.activeElement === this.root.querySelector('#refresh')
    this.root.innerHTML = this.snapshot ? this.renderSnapshot(this.snapshot) : this.renderUnavailable()
    this.bind()
    if (refreshFocused) this.root.querySelector<HTMLButtonElement>('#refresh')?.focus({ preventScroll: true })
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
        <h1>${this.busy ? 'Connecting' : 'Daemon unavailable'}</h1>
        <p>${escapeHtml(message)}</p>
        <button class="button button--primary" id="refresh" type="button" aria-disabled="${this.busy}">Try again</button>
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
          <button class="button" id="refresh" type="button" aria-label="Refresh local status" aria-disabled="${this.busy}"><span aria-hidden="true">↻</span> Refresh</button>
        </section>
        ${error}

        <dl class="summary-grid" aria-label="Connection summary">
          <div><dt>Network</dt><dd><code title="${escapeHtml(status.network_id)}">${escapeHtml(shortIdentity(status.network_id))}</code></dd></div>
          <div><dt>Address</dt><dd>${status.overlay_addresses[0] ? `<code>${escapeHtml(status.overlay_addresses[0])}</code>` : 'Not assigned'}</dd></div>
          <div><dt>Path</dt><dd>${escapeHtml(fallbackLabel(status.selected_path))}</dd></div>
          <div><dt>Identity lease</dt><dd>${escapeHtml(expiryLabel(status.controller.identity_lease_expires_at_unix_seconds))}</dd></div>
        </dl>

        <div class="content-grid">
          <section class="panel routes-panel">
            <header class="panel-heading">
              <h2>Private routes</h2>
              <span class="panel-context">${allRoutes.length} active</span>
            </header>
            ${allRoutes.length > 0
              ? `<ul class="route-list">${allRoutes.map(routeRow).join('')}</ul>`
              : '<div class="empty-row">No private routes are active.</div>'}
          </section>

          <aside class="panel session-panel">
            <header class="panel-heading"><h2>Exit</h2></header>
            <p>${escapeHtml(exitSummary)}</p>
            <dl class="session-facts">
              <div class="exit-readout"><dt>Current exit</dt><dd>${selectedExitPeer ? escapeHtml(peerLabel(selectedExitPeer)) : selectedExit ? escapeHtml(shortIdentity(selectedExit)) : 'None'}</dd></div>
              <div><dt>Interface</dt><dd>${escapeHtml(status.interface || 'Not active')}</dd></div>
              <div><dt>Relay</dt><dd title="${escapeHtml(status.relay)}">${escapeHtml(status.relay || 'Not active')}</dd></div>
              <div><dt>Certificate</dt><dd>${escapeHtml(expiryLabel(status.controller.certificate_not_after_unix_seconds))}</dd></div>
              <div><dt>Version</dt><dd>${escapeHtml(status.product_version || 'Unknown')}</dd></div>
            </dl>
            <ul class="capability-summary" aria-label="Desktop capabilities">
              <li><i class="capability-dot capability-dot--ready" aria-hidden="true"></i>Status and private routes</li>
              <li><i class="capability-dot ${exitAvailable ? 'capability-dot--ready' : ''}" aria-hidden="true"></i>${exitAvailable ? 'Exit control available' : 'Exit control not available'}</li>
              <li><i class="capability-dot ${snapshot.capabilities.snapshot_coherence ? 'capability-dot--ready' : ''}" aria-hidden="true"></i>${snapshot.capabilities.snapshot_coherence ? 'Restart-safe snapshot' : 'Legacy snapshot; restart detection unavailable'}</li>
              <li><i class="capability-dot ${snapshot.capabilities.connection_control ? 'capability-dot--ready' : ''}" aria-hidden="true"></i>${snapshot.capabilities.connection_control ? 'Connection control available' : 'Connect and profiles not available'}</li>
            </ul>
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
