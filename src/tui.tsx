// ScarletWitch TUI plugin — full cow dialog with two-level navigation + inline diff.
// Matches the fork's dialog-cow.tsx functionality.

import { getOptions, getCommand, clearCommands } from "./state.js"
import { commitCowGen, discardCow, listCowEntries, hasSupervisor, type CowEntry } from "./supervisor.js"
import { ScrollBoxRenderable, TextAttributes } from "@opentui/core"
import { createStore } from "solid-js/store"
import { createMemo, For, Show } from "solid-js"
import { useKeyboard, useTerminalDimensions, useRenderer } from "@opentui/solid"
import { createTwoFilesPatch } from "diff"
import fs from "fs"
import path from "path"

type CowGroup = { cmd_id: string; command: string; entries: CowEntry[] }

const LANG_MAP: Record<string, string> = {
  ".ts": "typescript", ".tsx": "typescript", ".js": "typescript", ".jsx": "typescript",
  ".py": "python", ".rs": "rust", ".go": "go", ".java": "java",
  ".c": "c", ".cpp": "cpp", ".h": "c", ".rb": "ruby", ".sh": "bash",
  ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".md": "markdown",
  ".html": "html", ".css": "css", ".sql": "sql", ".toml": "toml",
}

function filetype(input?: string): string {
  if (!input) return "none"
  return LANG_MAP[path.extname(input)] ?? "none"
}

function readFileOr(p: string, fb: string): string {
  try { return fs.readFileSync(p, "utf-8") } catch { return fb }
}

function cleanCommand(cmd: string): string {
  return cmd.replace(/^\/bin\/bash\s+-c\s+/, "").replace(/^\/bin\/sh\s+-c\s+/, "")
    .replace(/^bash\s+-c\s+/, "").replace(/^sh\s+-c\s+/, "")
}

// Find the previous version's cow_path for the same file (entry that appears
// earlier in the entries array). Falls back to the orig file on disk.
function findPrevPath(entry: CowEntry, entries: CowEntry[]): string {
  let prev: string | null = null
  for (const e of entries) {
    if (e === entry) break
    if (e.orig_path === entry.orig_path) prev = e.cow_path
  }
  return prev ?? entry.orig_path
}

function entryHasDiff(entry: CowEntry, entries: CowEntry[]): boolean {
  const origPath = findPrevPath(entry, entries)
  if (readFileOr(origPath, "") !== readFileOr(entry.cow_path, "")) return true
  try { if (fs.statSync(origPath).mode !== fs.statSync(entry.cow_path).mode) return true } catch {}
  return false
}

function buildGroups(entries: CowEntry[]): CowGroup[] {
  const map = new Map<string, CowGroup>()
  for (const e of entries) {
    const id = e.cmd_id || "unknown"
    if (!map.has(id)) {
      const display = getCommand(id) ?? cleanCommand(e.command ?? "?")
      map.set(id, { cmd_id: id, command: display, entries: [] })
    }
    map.get(id)!.entries.push(e)
  }
  return Array.from(map.values())
    .map(g => ({ ...g, entries: g.entries.filter(e => entryHasDiff(e, entries)) }))
    .filter(g => g.entries.length > 0)
}

// ================================================================
// Dialog component
// ================================================================

function DialogCow(props: {
  sessionID: string
  entries: CowEntry[]
  dialog: any
  theme: any
  onDone: () => void
}) {
  const dimensions = useTerminalDimensions()
  const theme = props.theme.current
  const [store, setStore] = createStore({
    cmdCursor: 0,
    level: "cmd" as "cmd" | "file",
    fileCursor: 0,
  })

  const groups = createMemo<CowGroup[]>(() => buildGroups(props.entries))
  const groupCount = () => groups().length

  const listHeight = createMemo(() => Math.floor(dimensions().height * 3 / 4) - 8)
  const diffView = createMemo(() => dimensions().width > 120 ? "split" as const : "unified" as const)

  let scroll: ScrollBoxRenderable | undefined

  function scrollToId(id: string) {
    if (!scroll) return
    function find(parent: any): any {
      for (const child of parent.getChildren()) {
        if (child.id === id) return child
        const found = find(child)
        if (found) return found
      }
      return null
    }
    const target = find(scroll)
    if (!target) return
    const y = target.y - scroll.y
    if (y >= scroll.height) scroll.scrollBy(y - scroll.height + 1)
    if (y < 0) scroll.scrollBy(y)
  }

  function makeDiffForEntry(entry: CowEntry): string {
    const origPath = findPrevPath(entry, props.entries)
    const oldContent = readFileOr(origPath, "")
    const newContent = readFileOr(entry.cow_path, "")
    if (oldContent !== newContent)
      return createTwoFilesPatch(entry.orig_path, entry.orig_path, oldContent, newContent)
    try {
      const oldMode = (fs.statSync(origPath).mode & 0o7777).toString(8)
      const newMode = (fs.statSync(entry.cow_path).mode & 0o7777).toString(8)
      if (oldMode !== newMode)
        return `--- ${entry.orig_path}\n+++ ${entry.orig_path}\n@@ permissions @@\n-mode: ${oldMode}\n+mode: ${newMode}\n`
    } catch {}
    return ""
  }

  const activeDiffKey = createMemo(() => {
    if (store.level !== "file") return ""
    const g = groups()[store.cmdCursor]
    if (!g) return ""
    const entry = g.entries[store.fileCursor]
    if (!entry) return ""
    return `${entry.cmd_id}:${entry.orig_path}`
  })

  function commitPrefix() {
    const g = groups()
    if (g.length === 0) return
    // Find max generation among entries in the selected prefix
    let maxGen = 0
    for (let i = 0; i <= store.cmdCursor && i < g.length; i++) {
      for (const e of g[i].entries) {
        const gen = e.generation ?? 0
        if (gen > maxGen) maxGen = gen
      }
    }
    commitCowGen(props.sessionID, maxGen)
    discardCow(props.sessionID)
    props.onDone()
    props.dialog.clear()
  }

  function enterFileLevel(fileIdx: number) {
    const g = groups()[store.cmdCursor]
    if (!g || g.entries.length === 0) return
    setStore("level", "file")
    setStore("fileCursor", Math.min(fileIdx, g.entries.length - 1))
    scrollToId(`cow-file-${store.cmdCursor}-${store.fileCursor}`)
  }

  // Scroll to a file entry, trying to show the diff area below it
  function scrollToFile(cmdIdx: number, fileIdx: number) {
    if (!scroll) return
    const id = `cow-file-${cmdIdx}-${fileIdx}`
    function find(parent: any): any {
      for (const child of parent.getChildren()) {
        if (child.id === id) return child
        const found = find(child)
        if (found) return found
      }
      return null
    }
    const target = find(scroll)
    if (!target) return
    // Scroll so the file entry is near the top, leaving room for the diff below
    const y = target.y - scroll.y
    const topMargin = 2
    if (y < topMargin) {
      scroll.scrollBy(y - topMargin)
    } else if (y >= scroll.height - 4) {
      scroll.scrollBy(y - topMargin)
    }
  }

  useKeyboard((evt: any) => {
    if (store.level === "cmd") {
      if (evt.name === "up" || evt.name === "k") {
        evt.preventDefault(); evt.stopPropagation()
        setStore("cmdCursor", Math.max(0, store.cmdCursor - 1))
        scrollToId(`cow-cmd-${store.cmdCursor}`)
        return
      }
      if (evt.name === "down" || evt.name === "j") {
        evt.preventDefault(); evt.stopPropagation()
        setStore("cmdCursor", Math.min(groupCount() - 1, store.cmdCursor + 1))
        scrollToId(`cow-cmd-${store.cmdCursor}`)
        return
      }
      if (evt.name === "right" || evt.name === "l") {
        evt.preventDefault(); evt.stopPropagation()
        enterFileLevel(0)
        return
      }
      if (evt.name === "return") {
        evt.preventDefault(); evt.stopPropagation()
        commitPrefix()
        return
      }
      if (evt.name === "d") {
        evt.preventDefault(); evt.stopPropagation()
        discardCow(props.sessionID)
        props.onDone()
        props.dialog.clear()
        return
      }
      return
    }

    if (store.level === "file") {
      const g = groups()[store.cmdCursor]
      if (!g) return
      if (evt.name === "up" || evt.name === "k") {
        evt.preventDefault(); evt.stopPropagation()
        if (store.fileCursor > 0) {
          setStore("fileCursor", store.fileCursor - 1)
          scrollToFile(store.cmdCursor, store.fileCursor)
        } else {
          setStore("level", "cmd")
          scrollToId(`cow-cmd-${store.cmdCursor}`)
        }
        return
      }
      if (evt.name === "down" || evt.name === "j") {
        evt.preventDefault(); evt.stopPropagation()
        if (store.fileCursor < g.entries.length - 1) {
          setStore("fileCursor", store.fileCursor + 1)
          scrollToFile(store.cmdCursor, store.fileCursor)
        } else if (store.cmdCursor < groupCount() - 1) {
          setStore("cmdCursor", store.cmdCursor + 1)
          setStore("level", "cmd")
          scrollToId(`cow-cmd-${store.cmdCursor}`)
        }
        return
      }
      if (evt.name === "left" || evt.name === "h") {
        evt.preventDefault(); evt.stopPropagation()
        setStore("level", "cmd")
        scrollToId(`cow-cmd-${store.cmdCursor}`)
        return
      }
      if (evt.name === "return") {
        evt.preventDefault(); evt.stopPropagation()
        commitPrefix()
        return
      }
      if (evt.name === "d") {
        evt.preventDefault(); evt.stopPropagation()
        discardCow(props.sessionID)
        props.onDone()
        props.dialog.clear()
        return
      }
      return
    }
  })

  const selectedCount = () => {
    const g = groups()
    let n = 0
    for (let i = 0; i <= store.cmdCursor && i < g.length; i++) n += g[i].entries.length
    return n
  }

  const helpLine1 = () =>
    store.level === "cmd"
      ? "↑↓:select  →:files diff  enter:commit prefix "
      : "↑↓:select  ←:back        enter:commit prefix "

  const helpLine2 = "d:discard all  esc:commit all"

  return (
    <box paddingLeft={2} paddingRight={2} gap={1}>
      <box flexDirection="row" justifyContent="space-between">
        <text attributes={TextAttributes.BOLD} fg={theme.text}>
          COW — commit first {store.cmdCursor + 1}/{groupCount()} commands ({selectedCount()} files)
        </text>
        <text fg={theme.textMuted}>esc:all</text>
      </box>

      <scrollbox
        ref={(r: ScrollBoxRenderable) => (scroll = r)}
        maxHeight={listHeight()}
        scrollbarOptions={{ visible: false }}
      >
        <For each={groups()}>
          {(group: CowGroup, groupIdx: () => number) => {
            const isIncluded = () => groupIdx() <= store.cmdCursor
            const isCmdCursor = () => store.level === "cmd" && groupIdx() === store.cmdCursor
            const isActiveGroup = () => groupIdx() === store.cmdCursor
            return (
              <box gap={0}>
                <box flexDirection="row" id={`cow-cmd-${groupIdx()}`}>
                  <text fg={isIncluded() ? theme.success : theme.textMuted}>
                    {isIncluded() ? "[x] " : "[ ] "}
                  </text>
                  <text
                    fg={isCmdCursor() ? theme.primary : isIncluded() ? theme.text : theme.textMuted}
                    attributes={isCmdCursor() ? TextAttributes.BOLD : TextAttributes.DIM}
                  >
                    $ {(() => { const c = cleanCommand(group.command); return c.length > 76 ? c.slice(0, 73) + "..." : c })()}
                  </text>
                </box>
                <For each={group.entries}>
                  {(entry: CowEntry, fileIdx: () => number) => {
                    const isFileCursor = () =>
                      store.level === "file" && isActiveGroup() && fileIdx() === store.fileCursor
                    const diffKey = () => `${entry.cmd_id}:${entry.orig_path}`
                    const showDiff = () => activeDiffKey() === diffKey()
                    return (
                      <box paddingLeft={4} id={`cow-file-${groupIdx()}-${fileIdx()}`}>
                        <box flexDirection="row">
                          <Show when={store.level === "file" && isActiveGroup()}>
                            <text fg={isFileCursor() ? theme.primary : theme.textMuted}>
                              {isFileCursor() ? "▸ " : "  "}
                            </text>
                          </Show>
                          <text
                            fg={isFileCursor() ? theme.primary : isIncluded() ? theme.text : theme.textMuted}
                            attributes={isFileCursor() ? TextAttributes.BOLD : 0}
                          >
                            {entry.orig_path}
                          </text>
                          <text fg={theme.accent}> {entry.operation}</text>
                        </box>
                        <Show when={showDiff()}>
                          <box paddingTop={1} paddingBottom={1}>
                            <diff
                              diff={makeDiffForEntry(entry)}
                              view={diffView()}
                              filetype={filetype(entry.orig_path)}
                              showLineNumbers={true}
                              width="100%"
                              wrapMode="word"
                              fg={theme.text}
                              addedBg={theme.diffAddedBg}
                              removedBg={theme.diffRemovedBg}
                              contextBg={theme.diffContextBg}
                              addedSignColor={theme.diffHighlightAdded}
                              removedSignColor={theme.diffHighlightRemoved}
                              lineNumberFg={theme.diffLineNumber}
                              lineNumberBg={theme.diffContextBg}
                              addedLineNumberBg={theme.diffAddedLineNumberBg}
                              removedLineNumberBg={theme.diffRemovedLineNumberBg}
                            />
                          </box>
                        </Show>
                      </box>
                    )
                  }}
                </For>
              </box>
            )
          }}
        </For>
      </scrollbox>

      <box paddingTop={1} paddingBottom={1}>
        <text fg={theme.textMuted}>{helpLine1()}</text>
        <text fg={theme.textMuted}>{helpLine2}</text>
      </box>
    </box>
  )
}

// ================================================================
// Plugin entry
// ================================================================

const plugin = {
  id: "scarletwitch",

  async tui(api: any) {
    api.event.on("session.turn.completed", (evt: any) => {
      const sessionID = evt?.properties?.sessionID
      if (!sessionID || !hasSupervisor(sessionID)) return

      const opts = getOptions()
      const cow = listCowEntries(sessionID, opts.review ?? "medium")
      if (!cow || cow.count === 0) return

      const groups = buildGroups(cow.entries)
      if (groups.length === 0) {
        const maxGen = cow.entries.reduce((m: number, e: CowEntry) => Math.max(m, e.generation ?? 0), 0)
        commitCowGen(sessionID, maxGen)
        discardCow(sessionID)
        return
      }

      let done = false
      api.ui.dialog.setSize("large")
      api.ui.dialog.replace(
        () => (
          <DialogCow
            sessionID={sessionID}
            entries={cow.entries}
            dialog={api.ui.dialog}
            theme={api.theme}
            onDone={() => { done = true }}
          />
        ),
        () => {
          if (!done) {
            const maxGen = cow.entries.reduce((m: number, e: CowEntry) => Math.max(m, e.generation ?? 0), 0)
            commitCowGen(sessionID, maxGen)
            discardCow(sessionID)
          }
        },
      )
    })
  },
}

export default plugin
