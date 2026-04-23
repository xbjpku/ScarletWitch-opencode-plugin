// ScarletWitch server plugin for opencode.
// Zero-config: auto-resolves binary paths from bundled submodule.

import type { PluginModule, PluginOptions } from "@opencode-ai/plugin"
import {
  ensureSupervisor,
  querySupervisor,
  hasSupervisor,
  listCowEntries,
  resolveOptions,
  type ScarletWitchOptions,
} from "./supervisor.js"
import { setOptions, setPendingCow, setCommand, clearCommands } from "./state.js"

const plugin: PluginModule = {
  id: "scarletwitch",

  async server(_input, options?: PluginOptions) {
    const opts = resolveOptions((options ?? {}) as ScarletWitchOptions)
    setOptions(opts)

    return {
      // Inject LD_PRELOAD + start supervisor.
      // Also inject SCARLET_CMD_ID=<callID> so the supervisor can group
      // syscalls by command even when multiple bash tools run in parallel.
      "shell.env": async (hookInput, output) => {
        const sessionID = hookInput.sessionID
        if (!sessionID) return
        const sv = await ensureSupervisor(sessionID, opts)
        output.env.LD_PRELOAD = opts.preload
        output.env.SANDBOX_SOCK_PATH = `${sv.dir}/${sessionID}.notify.sock`
        if (hookInput.callID) {
          output.env.SCARLET_CMD_ID = hookInput.callID
        }
      },

      // Store callID → command text mapping for TUI display
      "tool.execute.before": async (hookInput, output) => {
        if (hookInput.tool !== "bash") return
        const cmd = output.args?.command
        if (cmd && hookInput.callID) {
          setCommand(hookInput.callID, cmd)
        }
      },

      // Post-turn: query cow state, store for TUI, clear command map
      event: async ({ event }) => {
        if (event.type !== "session.turn.completed") return
        const props = event.properties as { sessionID?: string }
        const sessionID = props?.sessionID
        if (!sessionID || !hasSupervisor(sessionID)) return

        const cow = listCowEntries(sessionID, opts.review)
        if (!cow || cow.count === 0) {
          setPendingCow(null)
          clearCommands()
          return
        }
        setPendingCow({ sessionID, entries: cow.entries, deleted: cow.deleted })
        // Don't clear commands yet — TUI needs them for display
      },
    }
  },
}

export default plugin
