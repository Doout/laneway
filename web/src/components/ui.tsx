import { cloneElement, isValidElement, useId, type ButtonHTMLAttributes, type FormEvent, type ReactElement, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ChevronRight, Ellipsis, Search } from 'lucide-react'
import clsx from 'clsx'

export type ButtonVariant = 'primary' | 'secondary' | 'quiet' | 'danger'

export function Button({
  children,
  variant = 'secondary',
  to,
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { children: ReactNode; variant?: ButtonVariant; to?: string }) {
  const classes = clsx('button', `button--${variant}`, className)
  if (to) return <Link className={classes} to={to}>{children}</Link>
  return <button type={props.type ?? 'button'} className={classes} {...props}>{children}</button>
}

export function PageHeader({
  title,
  description,
  action,
}: {
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <header className="page-header">
      <div className="page-header__copy">
        <h1>{title}</h1>
        {description ? <p>{description}</p> : null}
      </div>
      {action ? <div className="page-header__action">{action}</div> : null}
    </header>
  )
}

export function Status({ children, tone = 'positive' }: { children: ReactNode; tone?: 'positive' | 'warning' | 'danger' | 'muted' }) {
  return <span className="status"><span className={clsx('status__dot', `status__dot--${tone}`)} aria-hidden="true" />{children}</span>
}

export function EntityTitle({ icon, children, subtitle }: { icon: ReactNode; children: ReactNode; subtitle?: ReactNode }) {
  const title = typeof children === 'string' ? children : undefined
  const subtitleTitle = typeof subtitle === 'string' ? subtitle : undefined
  return <span className="entity-title"><span className="entity-title__icon" aria-hidden="true">{icon}</span><span><strong title={title}>{children}</strong>{subtitle ? <small title={subtitleTitle}>{subtitle}</small> : null}</span></span>
}

export function Toolbar({ children, filters }: { children?: ReactNode; filters?: ReactNode }) {
  return <div className="toolbar"><div className="toolbar__primary">{children}</div>{filters ? <div className="toolbar__filters">{filters}</div> : null}</div>
}

export function SearchField({ label, placeholder, value, onChange }: { label: string; placeholder: string; value?: string; onChange?: (value: string) => void }) {
  return <label className="search-field"><Search aria-hidden="true" size={18} /><span className="sr-only">{label}</span><input type="search" placeholder={placeholder} value={value} onChange={event => onChange?.(event.target.value)} /></label>
}

export function FilterSelect({ label, children, value, onChange }: { label: string; children: ReactNode; value?: string; onChange?: (value: string) => void }) {
  return <label className="filter-select"><span className="sr-only">{label}</span><select value={value} onChange={event => onChange?.(event.target.value)}>{children}</select></label>
}

export interface DataColumn<T> {
  key: string
  label: string
  render: (row: T) => ReactNode
  align?: 'start' | 'end'
}

export function DataTable<T>({ columns, rows, rowKey, rowClassName, empty }: { columns: DataColumn<T>[]; rows: T[]; rowKey: (row: T) => string; rowClassName?: (row: T) => string | undefined; empty?: ReactNode }) {
  if (!rows.length && empty) return <div className="data-empty">{empty}</div>
  return <div className="table-wrap"><table className="data-table"><thead><tr>{columns.map(column => <th key={column.key} className={column.align === 'end' ? 'align-end' : undefined}>{column.label}</th>)}</tr></thead><tbody>{rows.map(row => <tr key={rowKey(row)} className={rowClassName?.(row)}>{columns.map(column => <td key={column.key} data-label={column.label} className={column.align === 'end' ? 'align-end' : undefined}>{column.render(row)}</td>)}</tr>)}</tbody></table></div>
}

export function KebabButton({ label = 'Open row actions', onClick }: { label?: string; onClick?: () => void }) {
  return <button className="icon-button" type="button" aria-label={label} onClick={onClick}><Ellipsis aria-hidden="true" size={18} /></button>
}

export function Section({ title, meta, action, children }: { title: string; meta?: ReactNode; action?: ReactNode; children: ReactNode }) {
  return <section className="section"><div className="section__header"><div><h2>{title}</h2>{meta ? <div className="section__meta">{meta}</div> : null}</div>{action}</div>{children}</section>
}

export function RecordList({ rows }: { rows: Array<[string, ReactNode]> }) {
  return <dl className="record-list">{rows.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
}

export function ResourceLink({ to, icon, title, meta, state }: { to: string; icon: ReactNode; title: ReactNode; meta?: ReactNode; state?: ReactNode }) {
  return <Link className="resource-link" to={to}><span className="resource-link__icon" aria-hidden="true">{icon}</span><span className="resource-link__copy"><strong>{title}</strong>{meta ? <small>{meta}</small> : null}</span>{state ? <span className="resource-link__state">{state}</span> : null}<ChevronRight aria-hidden="true" size={17} /></Link>
}

export function ActionPanel({ children }: { children: ReactNode }) {
  return <div className="action-panel">{children}</div>
}

export function DetailLayout({ identity, children }: { identity: ReactNode; children: ReactNode }) {
  return <div className="detail-layout"><aside>{identity}</aside><div className="detail-layout__content">{children}</div></div>
}

export function IdentityBlock({ icon, state, title, actions, metadata }: { icon: ReactNode; state: ReactNode; title?: string; actions?: ReactNode; metadata: Array<[string, ReactNode]> }) {
  return <div className="identity-block"><div className="identity-block__icon">{icon}</div>{title ? <h2>{title}</h2> : null}<div>{state}</div>{actions ? <div className="button-row">{actions}</div> : null}<dl className="metadata">{metadata.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl></div>
}

export function FormLayout({ form, review }: { form: ReactNode; review: ReactNode }) {
  return <div className="form-layout"><div>{form}</div><aside>{review}</aside></div>
}

export function FormStack({ children, onSubmit }: { children: ReactNode; onSubmit?: (event: FormEvent<HTMLFormElement>) => void }) {
  return <form className="form-stack" onSubmit={onSubmit}>{children}</form>
}

type FieldControlProps = {
  id?: string
  'aria-describedby'?: string
  'aria-invalid'?: boolean | 'true' | 'false' | 'grammar' | 'spelling'
}

export function Field({ label, hint, error, children }: { label: ReactNode; hint?: ReactNode; error?: ReactNode; children: ReactNode }) {
  const generatedId = useId()
  const control = isValidElement<FieldControlProps>(children) ? children as ReactElement<FieldControlProps> : null
  const controlId = control?.props.id ?? `${generatedId}-control`
  const hintId = `${generatedId}-hint`
  const errorId = `${generatedId}-error`
  const hasHint = hint !== undefined && hint !== null
  const hasError = error !== undefined && error !== null && error !== ''
  const describedBy = [control?.props['aria-describedby'], hasHint ? hintId : null, hasError ? errorId : null].filter(Boolean).join(' ') || undefined
  const enhancedControl = control
    ? cloneElement(control, {
        id: controlId,
        'aria-describedby': describedBy,
        'aria-invalid': hasError ? true : control.props['aria-invalid'],
      })
    : children

  return <div className="field"><label htmlFor={control ? controlId : undefined}>{label}</label>{enhancedControl}{hasHint ? <small id={hintId}>{hint}</small> : null}{hasError ? <small className="field__error" id={errorId} role="alert">{error}</small> : null}</div>
}

export function ChoiceGroup({ label, options, value, onChange }: { label: string; options: Array<{ value: string; label: string; description?: string; disabled?: boolean }>; value: string; onChange: (value: string) => void }) {
  return <fieldset className="choice-group"><legend>{label}</legend><div className="choice-group__options">{options.map(option => <button key={option.value} className="choice" type="button" aria-pressed={value === option.value} disabled={option.disabled} onClick={() => onChange(option.value)}><strong>{option.label}</strong>{option.description ? <small>{option.description}</small> : null}</button>)}</div></fieldset>
}

export function ReviewPanel({ title, rows, children }: { title: string; rows: Array<[string, ReactNode]>; children?: ReactNode }) {
  return <div className="review-panel"><h2>{title}</h2><dl className="review-list">{rows.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>{children}</div>
}

export function Callout({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'warning' | 'danger' }) {
  return <div className={clsx('callout', `callout--${tone}`)}>{children}</div>
}

export function TokenBox({ label, value, children }: { label: string; value: string; children?: ReactNode }) {
  return <div className="token-box"><span>{label}</span><code>{value}</code>{children}</div>
}

export function FlowPath({ items }: { items: ReactNode[] }) {
  return <div className="flow-path">{items.map((item, index) => <span key={index} className="flow-path__step">{item}</span>)}</div>
}

export function ConfirmPanel({ icon, title, description, children }: { icon: ReactNode; title: string; description: string; children: ReactNode }) {
  return <div className="confirm-panel"><span className="confirm-panel__icon" aria-hidden="true">{icon}</span><h2>{title}</h2><p>{description}</p>{children}</div>
}

export function EmptyState({ icon, title, description, action }: { icon: ReactNode; title: string; description?: string; action?: ReactNode }) {
  return <div className="empty-state"><span className="empty-state__icon" aria-hidden="true">{icon}</span><h2>{title}</h2>{description ? <p>{description}</p> : null}{action}</div>
}
