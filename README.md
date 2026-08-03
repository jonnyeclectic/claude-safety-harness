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
                   ├─ guard-bash.py     deny rm -rf / …  · ask sudo/force-push/rebase-on-protected
                   ├─ guard-paths.py    out-of-project Edit/Write gate (OFF by default)
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

## Auth context (API keys, Bedrock/Vertex)

`claudex` forwards the auth context you set in your shell — `ANTHROPIC_API_KEY`,
`ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_BASE_URL`,
`ANTHROPIC_MODEL`, `ANTHROPIC_SMALL_FAST_MODEL`, `CLAUDE_CODE_USE_BEDROCK`,
`CLAUDE_CODE_USE_VERTEX` — through to `claude`, and prints which source won:

```
claudex: auth → env (ANTHROPIC_API_KEY)
claudex: auth → cached login (no auth env set)
```

This matters because some terminals put their own shim in front of `claude` and
**scrub those variables on the way through** (cmux unsets them so a new pane can't
inherit a stale key). Launched from such a terminal, `claudex` used to hand `claude`
an environment with your key removed, and the session silently fell back to whatever
credentials were cached on disk — a wrong-account run, or a 401 with nothing on screen
explaining why. `claudex` now opts into the wrapper's preserve hatch whenever you
actually set auth context. Export `CLAUDEX_NO_AUTH_PASSTHROUGH=1` to defer to the
wrapper's scrub instead.

Two things this deliberately does *not* change:

- **`--strict` still scrubs `ANTHROPIC_API_KEY` from bash subprocesses.** Your own
  session authenticates fine; a nested `claude -p` inside sandboxed bash does not (and
  couldn't reach the API anyway under the strict network block). That's the point.
- **An API key in the wrong variable is still an error** — `claudex` just names it now.
  `CLAUDE_CODE_OAUTH_TOKEN` takes an OAuth token (`sk-ant-oat01-…`); an `sk-ant-api03-…`
  key there authenticates *at launch* and then 401s mid-session, so `claudex` warns.

The policy files live at `~/.claude/harness/sandbox.base.json` and `sandbox.strict.json` —
edit them to taste (add a `denyRead` path, loosen a rule); changes take effect on the next
`claudex` launch, no reinstall.

## Configure: out-of-project writes (worktrees, siblings)

Two independent layers govern writes outside the project:

- **The hook location gate is OFF by default** — `guard-paths.py` (Edit/Write) and
  `guard-bash.py` section 3 no longer prompt when a write/create/delete lands outside the
  working directory. So git worktrees, sibling dirs, and scaffolding "just work" without an
  approval prompt. Re-enable the prompt by exporting `HARNESS_GATE_OUTSIDE_WORKDIR=1`.
- **The OS sandbox still applies** to *bash* subprocesses: it only lets bash write to the
  project + temp (+ trusted roots). The built-in Edit/Write tools are not sandboxed, so for
  them the hook gate above is the only location boundary.

To let *bash* write across sibling checkouts / git worktrees under the sandbox, list them as
trusted roots (this also re-trusts them for the hook gate when it's enabled):

```bash
# ~/.claude/harness-trusted-roots.txt  — one path or glob per line
~/projects/my-app-worktrees/*
~/projects/shared-lib
```

`claudex` feeds each listed root into **both** the sandbox `allowWrite` set (so bash
subprocess writes there aren't blocked) **and** `--add-dir` (so the built-in file tools
reach them). The file is re-read on every launch; the current project dir is always
trusted automatically, so you only list *siblings*.

### What trusted roots can't reach

Claude Code hard-denies bash writes to **its own configuration surface**, and that deny beats
`allowWrite` — listing one of these as a trusted root silently does nothing at the kernel
level:

```
~/.claude/{skills,hooks,agents,commands,workflows,routines,rules,output-styles,
           plugins,local,jobs,daemon,shell-snapshots,session-env,backups,projects}
~/.claude/{settings.json,CLAUDE.md,scheduled_tasks.json,launch.json,loop.md}
<project>/.claude/{settings.json,settings.local.json,skills,hooks}
```

Keep it that way. A file under `~/.claude/skills` is *instructions that load into Claude's
context*, so a writable skills dir turns any hijacked bash subprocess — or a prompt injection
driving one — into a way to author its own instructions for your next session. This is the
one hole the harness most wants shut. Tools that install into those dirs (skill managers,
plugin installers) need to run from a normal terminal, not from inside `claudex`.

Two exceptions are *not* denied and do work as trusted roots: `~/.claude/plans` and
`~/.claude/projects/*/memory` — both are Claude Code output, not configuration.

One consequence worth knowing: `~/.claude/session-env` is on the deny list, so a **nested
`claude` cannot start** inside a `claudex` session — it exits with
`EPERM … mkdir '~/.claude/session-env/<uuid>'`. You therefore can't test a candidate sandbox
profile with `claude -p --settings <candidate>` from inside a sandboxed session; verify
profile changes after a real relaunch instead.

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
| **deny**  | hard block (irreversible) | `rm -rf /` · `~` · `/*`, fork bomb, `dd`/`mkfs`/`>` to a raw device, `chmod -R` on `/`. Quoted spellings count: `rm -rf "/"` and `bash -c "rm -rf /"` are the same command. *(One exception — see “throwaway `$HOME`” below.)* |
| **ask**   | forces a manual-approval prompt | `sudo`, force-push to a protected/shared branch, `git reset --hard <sha\|HEAD~N>`, `git clean -f`, `git rebase` on a protected branch, `curl\|bash`. *(Writes/deletes/edits outside the project also ask when `HARNESS_GATE_OUTSIDE_WORKDIR=1`; that gate is **off by default**.)* |
| **allow** | silent pass-through (full bypass speed) | tests, builds, `git status`, reads, `commit --no-verify`, mutations inside the project or `/tmp`, force-push/rebase of a topic branch, out-of-project file writes (gate off), `git reset --hard origin/main` |

- **`guard-bash.py`** — `PreToolUse` on `Bash`. Catastrophic denies and gray-area asks. The
  out-of-project write/delete ask (section 3) is **off by default** (`HARNESS_GATE_OUTSIDE_WORKDIR=1` to enable).

**Throwaway `$HOME`.** `rm -rf ~` / `rm -rf "$HOME"` is denied because it wipes *your home* —
but when `$HOME` is a temp dir it wipes nothing you own, and the deny is just in the way. So
it is allowed when the home in effect resolves under `/tmp`, `$TMPDIR`, `/var/folders`, …,
either because the command line retargeted it (`export HOME="$TMPDIR/x" && rm -rf "$HOME"`,
the usual test-isolation idiom) or because the session already runs under a throwaway home
(CI, a container, a sandboxed run). This relaxes the *home* target only: `rm -rf /`, a root
wildcard, and an `rm` hidden in a `$(…)` substitution stay denied no matter what `$HOME` is,
and a home under a configured *trusted root* is a real home — trusted roots are where you
keep things, so they do not count as throwaway.
- **`guard-paths.py`** — `PreToolUse` on `Edit|Write|MultiEdit|NotebookEdit`. The
  out-of-project file gate; **off by default** (`HARNESS_GATE_OUTSIDE_WORKDIR=1` to enable).
  When on it matters because the sandbox does **not** cover the built-in file tools.
- **`nudge-tests.py`** — `Stop` hook. If you edited source and no test/check ran after, it
  nudges once (auto-detects `make`/`pytest`/`npm test`/`cargo`/`go test`/`tox`/`gradle`/
  `mvn`). Silent on Q&A / docs-only / already-tested turns; loop-guarded.

Every `deny`/`ask` is logged to `~/.claude/harness-audit.log` (JSONL) so you can tune the
regex lists in `guard-bash.py` (`DENY_RULES`, `GRAY_RULES`) from real usage.

## `gh` doesn't work in the sandbox — use `ghapi`

Every `gh` network call fails inside the sandbox, and the error blames the wrong thing:

```
$ gh auth status
X Failed to log in to github.com using token (GITHUB_TOKEN)
  - The token in GITHUB_TOKEN is invalid.
```

The token is fine. `GH_DEBUG=api gh api user` shows the real error:

```
tls: failed to verify certificate: x509: OSStatus -26276   # errSecInternalComponent
```

Go verifies TLS certificates on macOS by calling the Security framework, which reaches
`trustd` over XPC — a mach lookup Seatbelt denies. So `gh` cannot complete *any* HTTPS
request here, and no wrapper can rescue it. Nothing about this is `gh`-specific — it's in
Go's standard TLS path — so expect other Go CLIs that verify certs in-process to fail the
same way (only `gh` has been observed doing so here). `SSL_CERT_FILE` and
`GODEBUG=x509usefallbackroots=1` do **not** help — Go always uses the platform verifier
when `RootCAs` is nil.

`curl` and `python` are unaffected: they verify against OpenSSL's own CA bundle in-process
and never talk to `trustd`. `bin/ghapi` (installed to `~/.local/bin/ghapi`) is a
`gh api`-compatible client built on curl:

```bash
ghapi auth status                      # the check `gh auth status` gets wrong
ghapi user --jq .login
ghapi user -i                          # include response headers (scopes, rate limit)
ghapi repos/{owner}/{repo}/pulls --paginate --jq '.[].title'
ghapi -X POST repos/{owner}/{repo}/pulls \
  -f title='Fix the thing' -f head=my-branch -f base=main -f body='...'
ghapi graphql -f query='{viewer{login}}'
```

`{owner}`/`{repo}` resolve from the `origin` remote, `-f`/`-F`/`-H`/`-i`/`--paginate`/
`--jq` behave as in `gh api`, and the token is passed via a curl `--config` file so it
never appears in `ps`. Other than `auth status`, the non-api subcommands (`gh pr create`,
`gh run watch`) are not reimplemented — use the REST endpoints directly.

`git` over HTTPS works normally (it uses curl), so ordinary fetch/push/PR flows are fine.

Under `claudex --strict` this is expected to fail, and that isn't a bug: strict mode denies
`GITHUB_TOKEN`/`GH_TOKEN` and blocks subprocess network entirely. Use plain `claudex` when
the task legitimately needs the GitHub API.

## Sandbox gotchas (things that fail in confusing ways)

Each of these has a trivial workaround; the cost is the time spent misdiagnosing them.
They all follow from the sandbox doing its job, and none indicate a broken install.

- **`gh` reports a TLS failure as an invalid token** — see the section above. The token
  is fine.
- **Don't use Python's `urllib` as an HTTP transport.** Its TLS works, but responses over
  ~5KB come back truncated (`IncompleteRead`, at a different offset each run) because the
  sandbox's HTTP/1.1 proxy hangs up early. curl negotiates HTTP/2 and returns the full
  body every time.
- **`/tmp` is not writable** — use `$TMPDIR`.
- **`/dev/stdout` cannot be opened**, so `open('/dev/stdout','w')` fails with `EPERM`.
  Writing to the already-open `sys.stdout` works; only the device path is blocked.
- **`git push -u` fails** with `could not lock config file .git/config`. The push itself
  succeeds — only the upstream-tracking write is denied, so name the remote and branch
  explicitly. Likewise `failed to store: 100001` is the keychain credential helper being
  unable to cache; it is noise, not a failure.
- **`make lint` needs `PYTHONPYCACHEPREFIX`** (already set in the Makefile). `compileall`
  writes `hooks/__pycache__` by default, and the sandbox denies writes to `hooks/` so the
  agent can't rewrite its own guards.
- **`install.sh` refuses to run inside a sandboxed session** — it probes `~/.claude` for
  writability and exits early. Run it from a normal terminal; the `!` prefix won't do.
  Note it *copies* rather than symlinks, so editing `bin/ghapi` in the repo does not
  change the installed copy until you reinstall.

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
