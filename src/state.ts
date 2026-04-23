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

// callID → command text mapping, set by tool.execute.before, read by TUI
const _cmdMap = new Map<string, string>()

export function setCommand(callID: string, command: string) {
  _cmdMap.set(callID, command)
}

export function getCommand(callID: string): string | undefined {
  return _cmdMap.get(callID)
}

export function getCommandMap(): Map<string, string> {
  return _cmdMap
}

export function clearCommands() {
  _cmdMap.clear()
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
