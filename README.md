# Claude Code Bypass Safety Harness

A safety harness for [Claude Code](https://claude.com/claude-code) sessions that
run with **`bypassPermissions`** (a.k.a. "dangerous" / skip-all-prompts mode).

Bypass mode removes the permission prompt on every tool call — fast, but nothing
stands between the model and `rm -rf /`. This plugin puts three guardrails back,
using the one mechanism that still works under bypass: **`PreToolUse` hooks
override bypass** (`deny` hard-blocks, `ask` forces a prompt), even when the
session is in bypass mode.

It's shipped as a Claude Code **plugin**, so installing it wires the hooks for
you — no hand-editing `settings.json`.

## Decision model

Deliberately small and auditable — three tiers:

| Tier | Behavior under bypass | Examples |
|------|-----------------------|----------|
| **deny**  | hard block (irreversible) | `rm -rf /` · `~` · `/*`, fork bomb, `dd`/`mkfs`/`>` to a raw device, `chmod -R` on `/` |
| **ask**   | forces a manual-approval prompt | `sudo`, force-push, `git reset --hard <sha\|HEAD~N>`, `git clean -f`, `commit --no-verify`, `curl\|bash` — **and any write/delete/edit that lands outside the working directory** |
| **allow** | silent pass-through (full bypass speed) | tests, builds, `git status`, reads anywhere, mutations inside the workdir or `/tmp`, `git reset --hard origin/main` (resync-to-upstream) |

Everything that isn't clearly dangerous stays out of your way.

## What's in the box

Three hooks (plus a shared helper):

- **`guard-bash.py`** — `PreToolUse` on `Bash`. Denies catastrophic commands,
  asks on gray-area ops and on mutations reaching outside the working directory.
- **`guard-paths.py`** — `PreToolUse` on `Edit|Write|MultiEdit|NotebookEdit`.
  Asks when the target file is outside the working directory.
- **`nudge-tests.py`** — `Stop` hook. If you edited source files and no
  test/check ran afterward, it nudges once to run the project's test command
  (auto-detected: `make check`/`test`, `pytest`, `npm test`, `cargo test`,
  `go test`, `tox`, `gradle`, `mvn`). Silent on Q&A / docs-only / already-tested
  turns; loop-guarded so it never traps a session.

Every `deny`/`ask` decision is logged to `~/.claude/harness-audit.log` (JSONL)
so you can tune the rules from real usage.

## Install

Requires Claude Code and `python3` on `PATH`.

```
/plugin marketplace add jonnyeclectic/claude-safety-harness
/plugin install bypass-safety-harness@claude-safety-harness
```

Or from the CLI:

```bash
claude plugin marketplace add jonnyeclectic/claude-safety-harness
claude plugin install bypass-safety-harness@claude-safety-harness
```

Hooks load at session start, so **start a new session** (or `/reload-plugins`)
to activate. Verify with `/hooks` — you should see the three scripts under
`PreToolUse` and `Stop`.

## Configure: trusted roots (loosen the location gate)

By default, anything outside your current working directory triggers an `ask`.
If you work across sibling checkouts / git worktrees, whitelist them so they
don't prompt:

```bash
cp harness-trusted-roots.example.txt ~/.claude/harness-trusted-roots.txt
# then edit — one path or glob per line, e.g.:
#   ~/myproject
#   ~/myproject-*
```

This file is read **fresh on every hook call**, so edits take effect
immediately — no restart. It relaxes **only** the out-of-workdir location gate;
`deny` and gray-area `ask` rules still apply everywhere.

## Tuning

The rules are plain regex lists at the top of `guard-bash.py`
(`DENY_RULES`, `GRAY_RULES`) and the trusted-roots logic in `harness_common.py`.
If a legitimate command gets gated, check `~/.claude/harness-audit.log` to see
exactly which rule fired, then adjust. (When editing a local clone, changes to
the installed copy require reinstalling the plugin; the trusted-roots file is
the zero-restart knob.)

## How it behaves in non-bypass modes

Harmless. In normal/ask or accept-edits modes the same `deny`/`ask` decisions
apply on top of the usual permission flow — you just get the extra hard blocks
on catastrophic commands.

## Uninstall

```
/plugin uninstall bypass-safety-harness@claude-safety-harness
```

Your `~/.claude/harness-trusted-roots.txt` and `~/.claude/harness-audit.log` are
left in place; delete them by hand if you want them gone.

## License

MIT — see [LICENSE](LICENSE).
