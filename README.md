# ScarletWitch-Opencode

> *"I have what I want, and no one will ever take it from me again."* — Wanda Maximoff

**ScarletWitch** is a Linux seccomp-based filesystem sandbox for AI coding agents. Like the Scarlet Witch's Hex, it warps reality for the processes inside — all bash commands execute without asking for permission, but nothing touches the real world. All mutations are trapped in a **copy-on-write illusion** until you decide what becomes canon. And unlike other sandboxes that force you to re-run the entire agent after review, ScarletWitch lets you **turn illusion into reality with a single commit** — no replays, no do-overs.

This is the **opencode plugin** — self-contained, zero-config. It bundles the [ScarletWitch](https://github.com/xbjpku/ScarletWitch) supervisor and builds it automatically.

## Quick Start

```bash
# 1. Clone with submodule
git clone --recursive https://github.com/xbjpku/ScarletWitch-Opencode.git

# 2. Build (automatic via postinstall)
cd ScarletWitch-Opencode && npm install

# 3. Add plugin to opencode
#    Server plugin → .opencode/opencode.json
#    TUI plugin    → .opencode/tui.json
```

**.opencode/opencode.json:**
```json
{
  "plugin": [
    "file:///path/to/ScarletWitch-Opencode/src/server.ts"
  ]
}
```

**.opencode/tui.json:**
```json
{
  "plugin": [
    "file:///path/to/ScarletWitch-Opencode/src/tui.tsx"
  ]
}
```

That's it. The plugin auto-detects the bundled supervisor, preload library, and whitelist. No manual path configuration needed.

## Whitelist

Edit `scarletwitch/whitelist.conf` to control which paths are writable without COW and which are unreadable:

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
    ["file:///path/to/ScarletWitch-Opencode/src/server.ts", {
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
- opencode with [`session.turn.completed` hook](https://github.com/xbjpku/opencode/tree/plugin-hooks)

## License

MIT
