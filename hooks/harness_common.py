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

# scratch/dev dirs are always fine to touch without a prompt
_SCRATCH = ("/tmp/", "/private/tmp/", "/var/folders/", "/dev/")


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
    if target.startswith(_SCRATCH) or target in ("/tmp", "/private/tmp"):
        return True
    return any(_match_root(target, raw) for raw in load_trusted_roots())
