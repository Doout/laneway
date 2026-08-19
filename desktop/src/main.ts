import '@fontsource-variable/manrope'
import { LanewayDesktop } from './app'
import { desktopApi } from './api'
import './styles.css'

const root = document.querySelector<HTMLElement>('#app')
if (!root) throw new Error('Laneway desktop root is missing')

new LanewayDesktop(root, desktopApi).start()
