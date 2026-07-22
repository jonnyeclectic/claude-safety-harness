#!/usr/bin/env python3
"""Shared helpers for the bypass safety harness guards.

The single source of truth for "is this path part of my workspace?" — used by
guard-bash.py and guard-paths.py so the out-of-workdir *location* gate can be
loosened in one place via ~/.claude/harness-trusted-roots.txt.

This only affects the location gate. Catastrophic denies (rm -rf /, dd to a
device, ...) and gray-area asks (sudo, force-push, curl|bash) still apply
everywhere, trusted root or not.
"""
import fnmatch
import os

TRUSTED_FILE = os.path.expanduser("~/.claude/harness-trusted-roots.txt")

# scratch dirs are always fine to touch without a prompt. Note /dev is NOT
# blanket-trusted: only the harmless character devices below (and /dev/fd/*,
# where realpath sends /dev/stdout etc.) — so a write to a raw disk like
# /dev/rdisk0 still falls through to the location gate.
_SCRATCH = ("/tmp/", "/private/tmp/", "/var/folders/", "/dev/fd/")
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


def is_trusted(target, cwd):
    """True if `target` is inside the working dir, a scratch dir, or a
    configured trusted root -> the harness should NOT prompt on location."""
    target = os.path.realpath(target)
    cwd = os.path.realpath(cwd)
    if target == cwd or target.startswith(cwd + os.sep):
        return True
    if target in _SAFE_DEV:
        return True
    if _is_claude_output(target):
        return True
    if target.startswith(_SCRATCH) or target in ("/tmp", "/private/tmp"):
        return True
    return any(_match_root(target, raw) for raw in load_trusted_roots())
