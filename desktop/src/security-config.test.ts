import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import capability from '../src-tauri/capabilities/default.json'

describe('desktop native authority surface', () => {
  it('grants the webview no Tauri core or plugin capabilities', () => {
    expect(capability.windows).toEqual(['main'])
    expect(capability.permissions).toEqual([])
  })

  it('registers only the typed read-only snapshot command', () => {
    const backend = readFileSync(new URL('../src-tauri/src/lib.rs', import.meta.url), 'utf8')
    expect(backend.match(/#\[tauri::command\]/g)).toHaveLength(1)
    expect(backend).toMatch(/generate_handler!\[desktop_snapshot\]/)
    expect(backend).not.toMatch(/desktop_set_exit/)
    expect(backend).not.toMatch(/std::process|Command::/)
  })
})
