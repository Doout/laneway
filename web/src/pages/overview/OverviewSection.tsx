import type { ReactNode } from 'react'
import { ArrowRight } from 'lucide-react'
import { Button } from '../../components/ui'
import './overview.css'

export function OverviewSection({ id, title, count, action, children }: {
  id: string
  title: string
  count?: number
  action?: { to: string; label: string }
  children: ReactNode
}) {
  return <section className="overview-section" aria-labelledby={id}>
    <header className="overview-section__header">
      <h2 id={id}>{title}</h2>
      {count !== undefined ? <span className="overview-section__count">{count}</span> : null}
      {action ? <Button className="overview-section__action" to={action.to} variant="quiet">{action.label} <ArrowRight aria-hidden="true" size={14} /></Button> : null}
    </header>
    {children}
  </section>
}
