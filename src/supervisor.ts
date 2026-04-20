// Supervisor lifecycle and communication.
// Auto-resolves binary paths from the bundled ScarletWitch submodule.

import { spawnSync, spawn } from "child_process"
import { statSync, existsSync } from "fs"
import { resolve, dirname } from "path"
import { fileURLToPath } from "url"

// ================================================================
// Auto-resolve paths relative to this package
// ================================================================

const __dirname = dirname(fileURLToPath(import.meta.url))
const PACKAGE_ROOT = resolve(__dirname, "..")
const SW_BUILD = resolve(PACKAGE_ROOT, "scarletwitch", "build")
const SW_WHITELIST = resolve(PACKAGE_ROOT, "scarletwitch", "whitelist.conf")

const DEFAULTS = {
  preload: resolve(SW_BUILD, "sandbox_preload.so"),
  supervisor: resolve(SW_BUILD, "supervisor"),
  whitelist: SW_WHITELIST,
  dir: "/tmp/scarletwitch",
  review: "medium" as const,
}

export type ScarletWitchOptions = {
  preload?: string
  supervisor?: string
  whitelist?: string
  dir?: string
  review?: "strict" | "medium" | "loose"
}

export function resolveOptions(opts: ScarletWitchOptions): Required<ScarletWitchOptions> {
  return {
    preload: opts.preload ?? DEFAULTS.preload,
    supervisor: opts.supervisor ?? DEFAULTS.supervisor,
    whitelist: opts.whitelist ?? DEFAULTS.whitelist,
    dir: opts.dir ?? DEFAULTS.dir,
    review: opts.review ?? DEFAULTS.review,
  }
}

// ================================================================
// Types
// ================================================================

export type CowEntry = {
  orig_path: string
  cow_path: string
  operation: string
  command: string
  timestamp: number
  generation: number
}

// ================================================================
// Supervisor lifecycle
// ================================================================

const supervisors = new Map<string, { pid: number; dir: string }>()

export async function ensureSupervisor(sessionID: string, opts: Required<ScarletWitchOptions>) {
  if (supervisors.has(sessionID)) return supervisors.get(sessionID)!

  if (!existsSync(opts.supervisor)) {
    console.error(`[scarletwitch] supervisor binary not found: ${opts.supervisor}`)
    console.error(`[scarletwitch] Run: cd ${PACKAGE_ROOT} && bash scripts/postinstall.sh`)
    throw new Error("ScarletWitch supervisor not built")
  }

  const args = ["--session", sessionID, "--dir", opts.dir]
  if (opts.whitelist) args.push("--from", opts.whitelist)

  spawn(opts.supervisor, args, { stdio: ["ignore", "ignore", "pipe"], detached: true })
  await new Promise((resolve) => setTimeout(resolve, 150))

  const entry = { pid: 0, dir: opts.dir }
  supervisors.set(sessionID, entry)
  return entry
}

// ================================================================
// Socket communication
// ================================================================

export function querySupervisor(sessionID: string, command: string, dir?: string): string {
  const sv = supervisors.get(sessionID)
  const d = dir ?? sv?.dir ?? DEFAULTS.dir
  const sockPath = `${d}/${sessionID}.ctrl.sock`
  try {
    const script = [
      `var c=require("net").createConnection(${JSON.stringify(sockPath)},function(){`,
      `c.write(${JSON.stringify(command + "\n")})});`,
      `var d="";c.on("data",function(k){d+=k});`,
      `c.on("end",function(){process.stdout.write(d);process.exit(0)});`,
      `c.on("error",function(e){process.stderr.write("ERR:"+e.message);process.exit(1)});`,
      `setTimeout(function(){c.destroy();process.stdout.write(d);process.exit(0)},2000);`,
    ].join("")
    const result = spawnSync("node", ["-e", script], { timeout: 5000, encoding: "utf-8" })
    return (result.stdout || "").trim()
  } catch {
    return ""
  }
}

export function hasSupervisor(sessionID: string): boolean {
  if (supervisors.has(sessionID)) return true
  try {
    return statSync(`${DEFAULTS.dir}/${sessionID}.ctrl.sock`).isSocket?.() ?? false
  } catch {
    return false
  }
}

// ================================================================
// COW operations
// ================================================================

export function listCowEntries(sessionID: string, level: string = "medium"): {
  entries: CowEntry[]
  deleted: string[]
  count: number
} | null {
  const raw = querySupervisor(sessionID, `LIST_COW ${level}`)
  if (!raw) return null
  try { return JSON.parse(raw) } catch { return null }
}

export function commitCowGen(sessionID: string, maxGen: number): { ok: boolean; committed?: number; error?: string } {
  const raw = querySupervisor(sessionID, `COMMIT_GEN ${maxGen}`)
  if (!raw) return { ok: false, error: "no response" }
  try { return JSON.parse(raw) } catch { return { ok: false, error: "parse error" } }
}

export function discardCow(sessionID: string): { ok: boolean } {
  const raw = querySupervisor(sessionID, "DISCARD")
  if (!raw) return { ok: false }
  try { return JSON.parse(raw) } catch { return { ok: false } }
}
