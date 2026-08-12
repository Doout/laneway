import '@testing-library/jest-dom/vitest'

function memoryStorage(): Storage {
  const values = new Map<string, string>()

  return {
    get length() { return values.size },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(key) },
    setItem: (key, value) => { values.set(key, String(value)) },
  }
}

// Node 26 exposes an optional global localStorage whose unconfigured getter
// shadows jsdom's implementation. Keep tests deterministic across Node runners.
if (!window.localStorage) {
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    value: memoryStorage(),
  })
}
