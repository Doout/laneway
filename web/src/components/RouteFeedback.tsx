import { FileQuestion, LoaderCircle, LockKeyhole, Network, RefreshCw, ServerOff, type LucideIcon } from 'lucide-react'
import { useId, type ReactNode } from 'react'
import { useControlPlane } from '../lib/control-plane'
import { BrandMark } from './BrandMark'
import { Button } from './ui'

function RouteMessage({ icon: Icon, title, children }: { icon: LucideIcon; title: string; children: ReactNode }) {
  const id = useId()
  return <section className="route-message" aria-labelledby={id}>
    <Icon className="route-message__icon" size={20} aria-hidden="true" />
    <div className="route-message__body">
      <h1 id={id}>{title}</h1>
      {children}
    </div>
  </section>
}

export function AccessDeniedPage() {
  return <RouteMessage icon={LockKeyhole} title="Access denied">
    <p>Your administrator account doesn’t have access to this page.</p>
    <Button to="/overview">Return to overview</Button>
  </RouteMessage>
}

export function NotFoundPage() {
  return <RouteMessage icon={FileQuestion} title="Page not found">
    <p>Choose a workspace from the navigation or return to the overview.</p>
    <Button to="/overview">Return to overview</Button>
  </RouteMessage>
}

export function InventoryUnavailablePage() {
  const { inventoryError, inventoryPending, refresh } = useControlPlane()
  return <RouteMessage icon={ServerOff} title="Inventory unavailable">
    <p role="alert">{inventoryError}</p>
    <Button onClick={() => void refresh()} disabled={inventoryPending}>
      <RefreshCw size={15} aria-hidden="true" />Retry
    </Button>
  </RouteMessage>
}

export function SelectNetworkPage() {
  const { inventory, selectNetwork } = useControlPlane()
  return <RouteMessage icon={Network} title="Select a network">
    <div className="route-message__networks">{inventory?.networks.map(network =>
      <Button key={network.network_id} onClick={() => selectNetwork(network.network_id)}>
        {network.name}
      </Button>
    )}</div>
  </RouteMessage>
}

export function LoadingInventory() {
  return <p className="inventory-loading" role="status"><LoaderCircle className="is-spinning" size={16} aria-hidden="true" />Loading authorized inventory…</p>
}

export function CheckingSession() {
  return <main className="session-loading">
    <div><BrandMark /><span role="status">Checking administrator session…</span></div>
  </main>
}
