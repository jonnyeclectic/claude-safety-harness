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

If file-based managed settings turn on the network allow-list
(``sandbox.network.allowManagedDomainsOnly``), ``allowLocalBinding`` is written
as false whatever the template says: on macOS it lets a subprocess reach
localhost without the proxy that enforces the allow-list.
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


def managed_settings_dir():
    """The directory Claude Code reads file-based managed settings from.

    Claude Code 2.1.274 always reads the fixed OS directory; it has no working
    override. ``CLAUDEX_MANAGED_SETTINGS_DIR`` exists only so the tests can
    point this at a scratch directory instead of the machine's real policy.
    """
    override = os.environ.get("CLAUDEX_MANAGED_SETTINGS_DIR")
    if override:
        return override
    if sys.platform == "darwin":
        return "/Library/Application Support/ClaudeCode"
    return "/etc/claude-code"


def read_managed_json(path):
    """Parse one managed file the way Claude Code reads it, or None.

    Claude Code decodes a leading UTF-16LE byte-order mark as UTF-16 and
    anything else as UTF-8, then strips one leading U+FEFF before parsing.
    Python's json refuses both marks, so skipping on them would miss an
    allow-list Claude Code applies.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        text = data.decode("utf-16-le" if data.startswith(b"\xff\xfe") else "utf-8")
        if text.startswith("\ufeff"):
            text = text[1:]
        return json.loads(text)
    except (OSError, ValueError):
        return None


def managed_allowlist_active(managed_dir):
    """True if file-based managed settings set allowManagedDomainsOnly.

    Reads what Claude Code's file tier reads: managed-settings.json, then
    managed-settings.d/*.json (dotfiles excluded, as glob excludes them). A
    file that isn't valid JSON is skipped here; Claude Code refuses to start
    with one, so there is no session to protect.

    Any file setting it to true counts, even if a later file sets something
    else. Claude Code lets later files win, but drops a file's whole
    ``sandbox`` key when any value in it is mistyped, so a later file can't be
    trusted to switch the allow-list off. Erring this way only costs local
    binding.

    The template's own ``allowLocalBinding: false`` doesn't make this
    redundant. Claude Code merges only the highest managed source into
    settings (server-managed, then an MDM profile, then these files) but reads
    ``allowManagedDomainsOnly`` from every source, so with org-pushed settings
    present the allow-list applies while the file's ``false`` is dropped. An
    allow-list pushed only through MDM or server-managed settings isn't seen
    here; it needs ``allowLocalBinding: false`` in that same source.
    """
    paths = [os.path.join(managed_dir, "managed-settings.json")]
    paths += sorted(glob.glob(os.path.join(managed_dir, "managed-settings.d", "*.json")))
    for path in paths:
        cfg = read_managed_json(path)
        sandbox = cfg.get("sandbox") if isinstance(cfg, dict) else None
        network = sandbox.get("network") if isinstance(sandbox, dict) else None
        if isinstance(network, dict) and network.get("allowManagedDomainsOnly") is True:
            return True
    return False


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

    if managed_allowlist_active(managed_settings_dir()):
        network = cfg.setdefault("sandbox", {}).setdefault("network", {})
        if network.get("allowLocalBinding") is True:
            sys.stderr.write(
                "claudex: managed network allow-list found; local port binding "
                "is off so nothing can reach localhost around it\n")
        network["allowLocalBinding"] = False

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)

    for d in roots:  # -> launcher turns each into `--add-dir <d>`
        print(d)
    return 0


if __name__ == "__main__":
    sys.exit(main())
