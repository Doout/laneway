import { invoke } from '@tauri-apps/api/core'
import type { DesktopApi, DesktopSnapshot } from './contract'

export const desktopApi: DesktopApi = {
  snapshot() {
    return invoke<DesktopSnapshot>('desktop_snapshot')
  },
}
