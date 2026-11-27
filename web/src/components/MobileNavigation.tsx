import { useEffect, useState, type ReactNode } from 'react'
import { useLocation } from 'react-router-dom'
import { Dialog, DialogBackdrop, DialogClose, DialogContent, DialogTitle, DialogTrigger } from '@ui-sdk/react/dialog'
import { Menu, X } from 'lucide-react'
import { BrandMark } from './BrandMark'

export function MobileNavigation({ children, account }: { children: ReactNode; account?: ReactNode }) {
  const location = useLocation()
  const [openAt, setOpenAt] = useState<string | null>(null)
  const open = openAt === location.key
  if (openAt !== null && !open) setOpenAt(null)

  useEffect(() => {
    if (!open) return
    const breakpoint = window.matchMedia('(max-width: 680px)')
    const closeOnDesktop = () => { if (!breakpoint.matches) setOpenAt(null) }
    breakpoint.addEventListener('change', closeOnDesktop)
    return () => breakpoint.removeEventListener('change', closeOnDesktop)
  }, [open])

  return <div className="mobile-navigation">
    <Dialog open={open} onOpenChange={next => setOpenAt(next ? location.key : null)}>
      <DialogTrigger className="mobile-navigation__trigger" aria-label="Menu"><Menu size={19} aria-hidden="true" /></DialogTrigger>
      <span className="mobile-wordmark"><BrandMark />Laneway</span>
      <DialogBackdrop className="mobile-navigation__backdrop" />
      <DialogContent className="mobile-navigation__sheet">
        <header><DialogTitle>Navigation</DialogTitle><DialogClose className="mobile-navigation__close" aria-label="Close menu"><X size={18} aria-hidden="true" /></DialogClose></header>
        <div className="mobile-navigation__links" onClick={event => {
          if (event.target instanceof Element && event.target.closest('a')) setOpenAt(null)
        }}>{children}</div>
        {account ? <footer>{account}</footer> : null}
      </DialogContent>
    </Dialog>
  </div>
}
