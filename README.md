# ScarletWitch-opencode-plugin

> *"I have what I want, and no one will ever take it from me again."* — Wanda Maximoff

**ScarletWitch** is a Linux seccomp-based filesystem sandbox for AI coding agents. Like the Scarlet Witch's Hex, it warps reality for the processes inside — all bash commands execute without asking for permission, but nothing touches the real world. All mutations are trapped in a **copy-on-write illusion** until you decide what becomes canon. And unlike other sandboxes that force you to re-run the entire agent after review, ScarletWitch lets you **turn illusion into reality with a single commit** — no replays, no do-overs.

This is the **opencode plugin** — self-contained, no fork needed. It bundles the [ScarletWitch](https://github.com/xbjpku/ScarletWitch) supervisor and builds it automatically.

## Quick Start

### 1. Get opencode with hook support

This plugin requires a `session.turn.completed` hook in opencode. A [PR is pending](https://github.com/anomalyco/opencode/pull/23650) to upstream (+9 lines). Once merged, any standard opencode install will work.

Until then, use the pre-patched fork:

```bash
git clone https://github.com/xbjpku/opencode.git
cd opencode && git checkout plugin-hooks
bun install && bun run build
```

### 2. Install the plugin

```bash
git clone --recursive https://github.com/xbjpku/ScarletWitch-opencode-plugin.git
cd ScarletWitch-opencode-plugin && npm install
```

### 3. Configure opencode

**`.opencode/opencode.json`** — add server plugin:
```json
{
  "plugin": [
    "file:///path/to/ScarletWitch-opencode-plugin/src/server.ts"
  ]
}
```

**`.opencode/tui.json`** — add TUI plugin:
```json
{
  "plugin": [
    "file:///path/to/ScarletWitch-opencode-plugin/src/tui.tsx"
  ]
}
```

That's it. The plugin auto-detects the bundled supervisor, preload library, and whitelist.

## Whitelist

Edit `scarletwitch/whitelist.conf` to control which paths are writable without asking for permissions and which are unreadable:

```ini
[write]
# Writable WITHOUT going through COW (pass-through).
# Everything else is intercepted by the sandbox.
/tmp/
/home/user/project/

[read]
# NOT readable (blacklist). Everything else is readable.
/secret/data/
```

## Options

Pass options to the server plugin for customization:

```json
{
  "plugin": [
    ["file:///path/to/ScarletWitch-opencode-plugin/src/server.ts", {
      "review": "strict"
    }]
  ]
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `review` | `"medium"` | `strict` (all versions), `medium` (DAG simplified), `loose` (final diff only) |
| `dir` | `"/tmp/scarletwitch"` | Session directory for COW files and sockets |

## Prerequisites

- Linux 5.9+ (seccomp user notifications)
- Rust toolchain + GCC (for building the supervisor — runs automatically on install)

## License

MIT
