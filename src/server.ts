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
import { setOptions, setPendingCow } from "./state.js"

const plugin: PluginModule = {
  id: "scarletwitch",

  async server(_input, options?: PluginOptions) {
    const opts = resolveOptions((options ?? {}) as ScarletWitchOptions)
    setOptions(opts)

    return {
      // Inject LD_PRELOAD + start supervisor + send BEGIN_COMMAND.
      // shell.env fires INSIDE the bash tool's execute(), after permissions
      // but before the actual command runs — this is the right time for both
      // supervisor startup and BEGIN_COMMAND (tool.execute.before fires too
      // early, before the supervisor exists).
      "shell.env": async (hookInput, output) => {
        const sessionID = hookInput.sessionID
        if (!sessionID) return
        const sv = await ensureSupervisor(sessionID, opts)
        output.env.LD_PRELOAD = opts.preload
        output.env.SANDBOX_SOCK_PATH = `${sv.dir}/${sessionID}.notify.sock`
        // Mark new command generation for per-command versioning
        querySupervisor(sessionID, "BEGIN_COMMAND", sv.dir)
      },

      // Post-turn: query cow state and store for TUI plugin
      event: async ({ event }) => {
        if (event.type !== "session.turn.completed") return
        const props = event.properties as { sessionID?: string }
        const sessionID = props?.sessionID
        if (!sessionID || !hasSupervisor(sessionID)) return

        const cow = listCowEntries(sessionID, opts.review)
        if (!cow || cow.count === 0) {
          setPendingCow(null)
          return
        }
        setPendingCow({ sessionID, entries: cow.entries, deleted: cow.deleted })
      },
    }
  },
}

export default plugin
