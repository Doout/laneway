import { LanewayDesktop } from './app'
import { desktopApi } from './api'
import './styles.css'

const root = document.querySelector<HTMLElement>('#app')
if (!root) throw new Error('Laneway desktop root is missing')

const darkMode = window.matchMedia('(prefers-color-scheme: dark)')
const applyTheme = () => { document.documentElement.dataset.theme = darkMode.matches ? 'dark' : 'light' }
darkMode.addEventListener('change', applyTheme)
applyTheme()

new LanewayDesktop(root, desktopApi).start()
