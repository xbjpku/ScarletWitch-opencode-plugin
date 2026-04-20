// Shared module-level state between server and TUI plugins.
// Both plugins run in the same Node.js process, so module state is shared.

import type { ScarletWitchOptions, CowEntry } from "./supervisor.js"

// Set by server plugin during init, read by TUI plugin
let _options: ScarletWitchOptions = {}

export function setOptions(opts: ScarletWitchOptions) {
  _options = { ...opts }
}

export function getOptions(): ScarletWitchOptions {
  return _options
}

// Pending cow data, set by server event hook, consumed by TUI
export type PendingCow = {
  sessionID: string
  entries: CowEntry[]
  deleted: string[]
}

let _pending: PendingCow | null = null

export function setPendingCow(data: PendingCow | null) {
  _pending = data
}

export function consumePendingCow(): PendingCow | null {
  const p = _pending
  _pending = null
  return p
}
