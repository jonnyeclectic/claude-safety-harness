#!/usr/bin/env python3
"""Shared helpers for the bypass safety harness guards.

The single source of truth for "is this path part of my workspace?" — used by
guard-bash.py and guard-paths.py so the out-of-workdir *location* gate can be
loosened in one place via ~/.claude/harness-trusted-roots.txt.

This only affects the location gate, plus (via is_scratch_root) the subset of
gray-area asks whose blast radius is confined to the directory they run in
(git rebase/reset --hard/clean -f/commit --no-verify/filter-branch in a
scratch or trusted-root clone). Gray-area ops whose effect reaches beyond the
local directory -- sudo, force-push, curl|bash -- still ask everywhere,
trusted root or not: a disposable clone doesn't make privilege escalation or
mutating a real remote safe.
"""
import fnmatch
import os
import tempfile

TRUSTED_FILE = os.path.expanduser("~/.claude/harness-trusted-roots.txt")


def _tmp_prefixes():
    """Realpath-normalized OS temp roots, always ending in os.sep so they only
    prefix-match whole path segments. Includes the static well-known dirs plus
    the LIVE per-user temp dir ($TMPDIR / tempfile.gettempdir()). On macOS
    $TMPDIR is /var/folders/xx/.../T which realpath-resolves under
    /private/var/folders — so the pre-resolve form alone never matches a
    realpath'd target. Resolving it here makes any $TMPDIR write trusted
    regardless of the machine's specific folder hash, not just a hardcoded
    list."""
    raw = ["/tmp", "/private/tmp", "/var/folders", "/private/var/folders",
           "/dev/fd"]
    for cand in (os.environ.get("TMPDIR"), tempfile.gettempdir()):
        if cand:
            raw.append(cand)
            raw.append(os.path.realpath(cand))
    seen, out = set(), []
    for p in raw:
        p = p.rstrip("/") + "/"
        if p not in seen:
            seen.add(p)
            out.append(p)
    return tuple(out)


# scratch dirs are always fine to touch without a prompt. Note /dev is NOT
# blanket-trusted: only the harmless character devices below (and /dev/fd/*,
# where realpath sends /dev/stdout etc.) — so a write to a raw disk like
# /dev/rdisk0 still falls through to the location gate.
_SCRATCH = _tmp_prefixes()
_SAFE_DEV = {"/dev/null", "/dev/zero", "/dev/tty", "/dev/stdin",
             "/dev/stdout", "/dev/stderr", "/dev/random", "/dev/urandom"}

# First-party Claude Code output locations under ~/.claude that the agent writes
# to as part of normal operation. These hold benign markdown/scratch, NOT secrets
# or config, so trust them to avoid an approval prompt every time. Everything else
# under ~/.claude (.credentials.json, settings.json, this harness, the audit log,
# and the session transcripts under projects/<slug>/) stays gated. is_trusted()
# realpath-normalizes the target first, so traversals like
# ~/.claude/plans/../settings.json resolve out of these prefixes and are NOT
# trusted.
#   - ~/.claude/plans/               plan-mode plan files
#   - ~/.claude/projects/*/memory/   per-project auto-memory files
_CLAUDE_OUTPUT_DIRS = tuple(
    os.path.realpath(os.path.expanduser(p)) + os.sep
    for p in ("~/.claude/plans",)
)
_CLAUDE_PROJECTS = os.path.realpath(os.path.expanduser("~/.claude/projects"))


def _is_claude_output(target):
    """True if realpath `target` is inside a first-party Claude Code output dir:
    ~/.claude/plans/... or ~/.claude/projects/<slug>/memory/... . Scoped to the
    memory/ subdir so session transcripts (projects/<slug>/*.jsonl) stay gated."""
    if target.startswith(_CLAUDE_OUTPUT_DIRS):
        return True
    if target.startswith(_CLAUDE_PROJECTS + os.sep):
        # rest = ["<slug>", "memory", ...]; exactly one slug segment, then memory/
        rest = target[len(_CLAUDE_PROJECTS) + 1:].split(os.sep)
        return len(rest) >= 2 and rest[1] == "memory"
    return False


def load_trusted_roots():
    """Return the raw (unexpanded) trusted-root lines, sans comments/blanks."""
    roots = []
    try:
        with open(TRUSTED_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    roots.append(line)
    except OSError:
        pass
    return roots


def _match_root(target, raw):
    """True if realpath `target` is at/under trusted-root spec `raw`.

    `raw` may be a plain dir (prefix match on the resolved path) or a glob
    (e.g. ~/boost-*), matched with fnmatch against the target and its children.
    """
    raw = os.path.expandvars(os.path.expanduser(raw))
    if any(ch in raw for ch in "*?["):
        return (fnmatch.fnmatch(target, raw)
                or fnmatch.fnmatch(target, raw.rstrip("/") + "/*"))
    root = os.path.realpath(raw)
    return target == root or target.startswith(root + os.sep)


def outside_workdir_gate_enabled():
    """Whether the out-of-working-directory FILE gate is active.

    OFF by default: the harness owner relaxed it, so file writes -- creating,
    overwriting, or editing a file, and the Bash file-mutators/redirects that do
    the same -- are NOT prompted just for landing outside the working directory.
    That makes git worktrees, sibling dirs, and scaffolding "just work". Set
    HARNESS_GATE_OUTSIDE_WORKDIR=1 (or true/yes/on) to re-enable the location
    prompt. Independent of everything else: catastrophic denies (rm -rf /, mkfs,
    ...) and gray-area asks (sudo, force-push, curl|bash, rebase on a protected
    branch) still fire regardless of this setting."""
    return os.environ.get("HARNESS_GATE_OUTSIDE_WORKDIR", "").strip().lower() in (
        "1", "true", "yes", "on")


def is_trusted(target, cwd):
    """True if `target` is inside the working dir, a scratch dir, or a
    configured trusted root -> the harness should NOT prompt on location.

    NB: only consulted when outside_workdir_gate_enabled() is True; with the gate
    off (the default) the guards allow any location without reaching this."""
    target = os.path.realpath(target)
    cwd = os.path.realpath(cwd)
    if target == cwd or target.startswith(cwd + os.sep):
        return True
    if target in _SAFE_DEV:
        return True
    if _is_claude_output(target):
        return True
    # startswith(_SCRATCH) matches children; also trust the temp roots
    # themselves (target == the dir, with the trailing sep stripped).
    if target.startswith(_SCRATCH) or any(target == p[:-1] for p in _SCRATCH):
        return True
    return any(_match_root(target, raw) for raw in load_trusted_roots())


def is_temp_path(path):
    """True if `path` sits in (or IS) an OS temp root -- /tmp, /private/tmp,
    /var/folders, $TMPDIR, ... -- i.e. a genuinely throwaway location the OS
    itself reclaims.

    Strictly narrower than is_scratch_root(): configured trusted roots do NOT
    count. Used for the one decision where "disposable" has to mean literally
    temporary rather than "the owner declared this location fine to write in":
    relaxing guard-bash's whole-home `rm -rf` deny when $HOME is a throwaway
    home. A trusted root is a place you keep things; a temp dir is not, and
    only the latter makes wiping an entire home tree a non-event."""
    path = os.path.realpath(path)
    return path.startswith(_SCRATCH) or any(path == p[:-1] for p in _SCRATCH)


def is_scratch_root(path):
    """True if `path` ITSELF (no separate cwd to compare against) sits inside
    a scratch/tmp root or a configured trusted root.

    Distinct from is_trusted(): that one always trivially trusts target==cwd,
    which is right for "does this write stay inside the working dir" but
    wrong here -- we're asking "is the directory a git op runs in disposable
    enough that rewriting its history needs no confirmation," and every
    directory is trivially == itself. Used to loosen the LOCAL subset of
    guard-bash's gray-area asks (rebase, reset --hard, clean -f, commit
    --no-verify, filter-branch) for loop/remediation clones under /tmp or a
    trusted root, while force-push/sudo/curl|bash keep asking everywhere."""
    if is_temp_path(path):
        return True
    return any(_match_root(os.path.realpath(path), raw)
               for raw in load_trusted_roots())
