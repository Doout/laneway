type BrandMarkProps = {
  className?: string
}

export function BrandMark({ className }: BrandMarkProps) {
  return <img className={['brand-mark', className].filter(Boolean).join(' ')} src="/laneway-mark.svg" alt="" aria-hidden="true" width="24" height="24" />
}
