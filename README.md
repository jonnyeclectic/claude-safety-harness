# Claude Code Safety Harness

Run [Claude Code](https://claude.com/claude-code) in **`--dangerously-skip-permissions`**
("bypass" / YOLO) mode with a real wall around your machine — writes confined to the
current project, secrets and the rest of `$HOME` out of reach — instead of trusting the
model not to wander.

Two parts that work together:

1. **`claudex`** — a launcher that starts `claude` in bypass mode wrapped in Claude Code's
   built-in **OS sandbox** (Apple Seatbelt on macOS, bubblewrap on Linux). This is the
   *hard* boundary: bash subprocess writes outside the project + temp are blocked **at the
   syscall level** — no dialog, no way for the model (or a prompt-injection) to talk its
   way past. `claudex --strict` also cuts subprocess network and hides your secrets.
2. **`bypass-safety-harness`** — a Claude Code **plugin** (three `PreToolUse`/`Stop` hooks)
   that adds the advisory layer: hard-deny catastrophic commands, prompt on out-of-project
   edits and gray-area ops, and nudge you to run tests before finishing.

## Why this design

Under `--dangerously-skip-permissions`, per-action prompts, allow-rules, and the
working-directory boundary are all gone. Only **three** guards still fire — and this
harness uses all three:

| Guard | Covers | In this harness |
|---|---|---|
| **OS sandbox** (kernel-enforced) | writes/reads/network of **all bash subprocesses** — even `python -c`, `sed -i`, `find -delete` | `claudex` (via `--settings`) |
| **`permissions.deny`** | the built-in **Read/Edit/Write** tools + recognized file commands | `claudex --strict` |
| **`PreToolUse` hooks** | anything, programmatically (deny / ask) | the plugin |

The sandbox covers the gap the hooks can't (arbitrary subprocesses); the hooks cover the
gap the sandbox can't (the built-in file tools aren't sandboxed). Belt and suspenders.

```
  claudex  ──►  claude --dangerously-skip-permissions --settings <sandbox> --add-dir <trusted>
                   │
                   ├─ OS sandbox        writes → project + temp (+ trusted roots)   [HARD WALL]
                   ├─ guard-bash.py     deny rm -rf / …  · ask sudo/force-push/out-of-cwd
                   ├─ guard-paths.py    ask on Edit/Write outside the project
                   └─ nudge-tests.py    "you edited code but didn't run tests"
```

## Install

Requires Claude Code and `python3` on `PATH` (macOS has Seatbelt built in; on Linux
`sudo apt-get install bubblewrap socat`).

```bash
git clone https://github.com/jonnyeclectic/claude-safety-harness
cd claude-safety-harness
./install.sh
```

`install.sh` is idempotent and **never edits your `~/.claude/settings.json`** (the sandbox
is applied per-launch by `claudex`). It:

- installs the plugin (hooks) at **user scope** so they load in every session;
- copies the sandbox policy files + helper to `~/.claude/harness/`;
- installs the `claudex` launcher to `~/.local/bin/`;
- seeds `~/.claude/harness-trusted-roots.txt`.

Start a **new** session afterwards so the hooks load (verify with `/hooks`).

## Usage

```bash
cd ~/projects/my-app
claudex             # sandboxed bypass session, right here
claudex --strict    # + no subprocess network, secrets hidden
claudex -p "…"      # any extra args pass straight through to `claude`
```

What each mode enforces (all **verified** against Claude Code 2.1.216 on macOS):

| | `claudex` | `claudex --strict` |
|---|---|---|
| Write outside project + temp | 🚫 blocked at syscall | 🚫 blocked at syscall |
| Write inside project / temp / trusted roots | ✅ allowed | ✅ allowed |
| Subprocess network (`curl`, `npm i`, `pip`, `git fetch`) | ✅ open | 🚫 blocked (`403` at the proxy) |
| Read `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc`, … | ✅ readable | 🚫 blocked at syscall |
| Secret env vars (`GITHUB_TOKEN`, `AWS_*`, `*_API_KEY`) in subprocesses | visible | 🚫 scrubbed to empty |
| Built-in `Read`/`Edit` of the above secrets | (hook `ask` only) | 🚫 `permissions.deny` |
| Claude's own model API | ✅ | ✅ (unaffected by the subprocess network block) |

Use plain `claudex` for everyday work where the agent needs to install deps or hit APIs;
switch to `--strict` when you don't trust the task or the repo (untrusted PRs, random
`npm`-heavy code) and want it walled off from the network and your credentials.

The policy files live at `~/.claude/harness/sandbox.base.json` and `sandbox.strict.json` —
edit them to taste (add a `denyRead` path, loosen a rule); changes take effect on the next
`claudex` launch, no reinstall.

## Configure: trusted roots

By default the sandbox only lets bash write to the project + temp, and the hooks `ask`
before touching anything outside the project. If you work across sibling checkouts / git
worktrees, list them so they're writable **and** don't prompt:

```bash
# ~/.claude/harness-trusted-roots.txt  — one path or glob per line
~/projects/my-app-worktrees/*
~/projects/shared-lib
```

`claudex` feeds each listed root into **both** the sandbox `allowWrite` set (so bash
subprocess writes there aren't blocked) **and** `--add-dir` (so the built-in file tools
reach them). The file is re-read on every launch; the current project dir is always
trusted automatically, so you only list *siblings*.

## Optional: a true global network allow-list

`claudex --strict` blocks **all** subprocess network. If instead you want an *allow-list*
(only Anthropic + npm + GitHub reachable, everything else blocked) you have to install it
as **managed settings**, because a launcher-scoped allow-list isn't enforceable
(`allowedDomains` alone doesn't deny others, and `deniedDomains:["*"]` blocks even the
allowed hosts — deny wins). Managed settings can express it:

```bash
sudo ./install.sh --managed-allowlist    # writes the OS managed-settings.json
```

⚠️ This is **global**: it restricts *every* claude session on the machine (plain `claude`
and base `claudex` too), not just `--strict`. Edit `settings/managed-network-allowlist.json`
first to set the domains you want. Undo with `sudo ./uninstall.sh --managed-allowlist`.

## The hooks (advisory layer)

Deliberately small and auditable — three tiers, applied in **every** session (they're
harmless in normal/ask modes, adding just the catastrophic hard-blocks):

| Tier | Behavior under bypass | Examples |
|------|-----------------------|----------|
| **deny**  | hard block (irreversible) | `rm -rf /` · `~` · `/*`, fork bomb, `dd`/`mkfs`/`>` to a raw device, `chmod -R` on `/` |
| **ask**   | forces a manual-approval prompt | `sudo`, force-push, `git reset --hard <sha\|HEAD~N>`, `git clean -f`, `commit --no-verify`, `curl\|bash` — **and any write/delete/edit landing outside the project** |
| **allow** | silent pass-through (full bypass speed) | tests, builds, `git status`, reads, mutations inside the project or `/tmp`, `git reset --hard origin/main` |

- **`guard-bash.py`** — `PreToolUse` on `Bash`. Catastrophic denies, gray-area asks,
  out-of-project mutation asks.
- **`guard-paths.py`** — `PreToolUse` on `Edit|Write|MultiEdit|NotebookEdit`. Asks when the
  target file is outside the project (the sandbox does **not** cover the built-in file
  tools, so this hook is their boundary even under `claudex`).
- **`nudge-tests.py`** — `Stop` hook. If you edited source and no test/check ran after, it
  nudges once (auto-detects `make`/`pytest`/`npm test`/`cargo`/`go test`/`tox`/`gradle`/
  `mvn`). Silent on Q&A / docs-only / already-tested turns; loop-guarded.

Every `deny`/`ask` is logged to `~/.claude/harness-audit.log` (JSONL) so you can tune the
regex lists in `guard-bash.py` (`DENY_RULES`, `GRAY_RULES`) from real usage.

## Limitations (know what this does and doesn't stop)

- The sandbox wraps **bash subprocesses**, not the built-in `Read`/`Edit`/`Write` tools —
  those are governed by the hooks + `--strict` deny rules. Both layers are needed.
- `claudex` (non-strict) leaves the network open, so a prompt-injection that reads an
  in-project secret could still exfiltrate it. Use `--strict` (or the managed allow-list)
  for untrusted work.
- The `--strict`/managed network filter matches on hostname (SNI); a determined attacker
  could domain-front. It's strong risk-reduction, not a cryptographic boundary.
- For fully unattended runs, prefer a container/VM (e.g. Anthropic's devcontainer with its
  iptables egress firewall) — that isolates the kernel and network, which no host-level
  sandbox can fully do.

## Uninstall

```bash
./uninstall.sh                        # remove launcher + policy files + plugin
sudo ./uninstall.sh --managed-allowlist   # if you installed the global allow-list
```

Your `~/.claude/harness-trusted-roots.txt` and `~/.claude/harness-audit.log` are left in
place; delete them by hand if you want them gone.

## License

MIT — see [LICENSE](LICENSE).
