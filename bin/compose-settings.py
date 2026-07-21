#!/usr/bin/env python3
"""Compose the effective claudex sandbox settings for a launch.

Reads a policy template (sandbox.base.json / sandbox.strict.json), injects the
current project's trusted sibling roots into ``sandbox.filesystem.allowWrite`` so
bash-subprocess writes to whitelisted siblings aren't kernel-blocked by the OS
sandbox, and writes the merged settings to <out_path>.

The expanded, existing trusted-root directories are printed one-per-line to
stdout so the launcher can also pass them as ``--add-dir`` (which governs the
built-in Read/Edit/Write tools, a layer the sandbox does not cover).

Usage:  compose-settings.py <template.json> <trusted-roots.txt|NONE> <out.json>

Note: ``sandbox.filesystem.allowWrite`` is ADDITIVE — the current working
directory and the session temp dir stay writable by default, so we never need to
re-add them here.
"""
import glob
import json
import os
import sys


def expand_roots(path):
    """Return realpath'd, de-duplicated existing dirs from a trusted-roots file.

    Format matches ~/.claude/harness-trusted-roots.txt: one path or glob per
    line; blank lines and full-line ``#`` comments ignored. Globs (``* ? []``)
    are expanded; only entries that resolve to real directories are kept.
    """
    dirs = []
    if not path or path == "NONE":
        return dirs
    try:
        fh = open(path, encoding="utf-8")
    except OSError:
        return dirs
    with fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            spec = os.path.expandvars(os.path.expanduser(line))
            matches = glob.glob(spec) if any(c in spec for c in "*?[") else [spec]
            for m in matches:
                if os.path.isdir(m):
                    dirs.append(os.path.realpath(m))
    seen, out = set(), []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def main():
    if len(sys.argv) != 4:
        sys.stderr.write(
            "usage: compose-settings.py <template.json> <trusted-roots|NONE> <out.json>\n")
        return 2
    template, roots_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(template, encoding="utf-8") as fh:
        cfg = json.load(fh)

    roots = expand_roots(roots_path)
    if roots:
        allow_write = (cfg.setdefault("sandbox", {})
                          .setdefault("filesystem", {})
                          .setdefault("allowWrite", []))
        for d in roots:
            if d not in allow_write:
                allow_write.append(d)

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)

    for d in roots:  # -> launcher turns each into `--add-dir <d>`
        print(d)
    return 0


if __name__ == "__main__":
    sys.exit(main())
