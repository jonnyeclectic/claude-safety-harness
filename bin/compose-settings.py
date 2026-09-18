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

Exits 4 without writing anything when the project's own settings widen the
sandbox (``sandbox.excludedCommands``, ``sandbox.filesystem.allowWrite`` or
``allowRead``), which no ``--settings`` file can undo.

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
import stat
import sys

# Claude Code reads a settings file through a 2 MiB cap; past that it gives up,
# so anything larger cannot be policy it applies.
MAX_SETTINGS_BYTES = 2 * 1024 * 1024


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
        # Not just "does it exist": a FIFO at .claude/settings.json blocks
        # open() forever, waiting for a writer that never comes, and claudex
        # would hang before it ever reached `claude`.
        if not stat.S_ISREG(os.stat(path).st_mode):
            return None
        with open(path, "rb") as fh:
            data = fh.read(MAX_SETTINGS_BYTES + 1)
        if len(data) > MAX_SETTINGS_BYTES:
            return None
        text = data.decode("utf-16-le" if data.startswith(b"\xff\xfe") else "utf-8")
        if text.startswith("\ufeff"):
            text = text[1:]
        if not text.strip():
            return {}  # Claude Code reads an empty settings file as {}
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


def find_git_root(start):
    """The *canonical* git root above `start`, the way Claude Code resolves it.

    Claude Code anchors `.claude/settings.local.json` at the git root while
    `.claude/settings.json` is anchored at the launch directory, so both have
    to be looked for separately.

    In a linked worktree `.git` is a FILE holding `gitdir: <path>`, and the
    settings that count live in the MAIN checkout: Claude Code follows that
    pointer, and its `commondir`, back there. Stopping at the worktree would
    check a directory Claude Code does not read -- and worktrees are the
    isolation story this harness recommends, which would make the safer
    workflow the exposed one. Other `.git`-file layouts (a submodule, `git
    init --separate-git-dir`) have no `commondir`, and Claude Code anchors at
    the checkout itself, so this falls back to the directory holding the file.
    """
    path = os.path.realpath(start)
    while True:
        dot_git = os.path.join(path, ".git")
        if os.path.isdir(dot_git):
            return path
        if os.path.isfile(dot_git):
            return main_worktree_root(dot_git) or path
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent


def main_worktree_root(dot_git_file):
    """The main checkout behind a worktree's `.git` file, or None."""
    try:
        with open(dot_git_file, encoding="utf-8") as fh:
            pointer = fh.read().strip()
    except OSError:
        return None
    if not pointer.startswith("gitdir:"):
        return None
    git_dir = pointer.split(":", 1)[1].strip()
    if not os.path.isabs(git_dir):
        git_dir = os.path.join(os.path.dirname(dot_git_file), git_dir)
    git_dir = os.path.realpath(git_dir)
    try:  # `commondir` points at the main .git; only a worktree has one
        with open(os.path.join(git_dir, "commondir"), encoding="utf-8") as fh:
            common = os.path.realpath(os.path.join(git_dir, fh.read().strip()))
    except OSError:
        return None
    # Claude Code requires the same shape before it re-anchors: the git dir
    # must sit in <common>/worktrees/. A submodule's .git file, or one written
    # by `git init --separate-git-dir`, points somewhere else entirely, and
    # Claude Code then anchors at the checkout itself -- so must we.
    if os.path.realpath(os.path.dirname(git_dir)) != os.path.join(common, "worktrees"):
        return None
    root = os.path.dirname(common)
    return root if os.path.isdir(root) else None


def project_settings_paths(project_dir):
    """The repo-owned settings files Claude Code merges for this launch."""
    git_root = find_git_root(project_dir)
    paths = [os.path.join(project_dir, ".claude", "settings.json"),
             os.path.join(project_dir, ".claude", "settings.local.json")]
    if git_root and os.path.realpath(git_root) != os.path.realpath(project_dir):
        paths.append(os.path.join(git_root, ".claude", "settings.local.json"))
    return list(dict.fromkeys(paths))


# Sandbox keys a repo's own settings can set that widen the wall, and that the
# `--settings` file cannot take back, because the settings merge concatenates
# arrays: claudex can add to each list, never empty it.
#   excludedCommands        commands Claude Code runs OUTSIDE the sandbox
#   filesystem.allowWrite   host paths a subprocess may write
#   filesystem.allowRead    paths re-opened inside --strict's denyRead (~/.ssh)
#   network.allowUnixSockets    a socket to a daemon on the host
#   network.allowMachLookup     a mach service outside the sandbox
PROJECT_SANDBOX_KEYS = (("excludedCommands",),
                        ("filesystem", "allowWrite"),
                        ("filesystem", "allowRead"),
                        ("network", "allowUnixSockets"),
                        ("network", "allowMachLookup"))


def project_sandbox_overrides(project_dir):
    """[(path, {"key.path": [values]})] for repo settings that widen the sandbox.

    The value is None when the file exists but can't be parsed. That counts as
    a hit: a file the harness can't read is a file it can't clear.
    """
    hits = []
    for path in project_settings_paths(project_dir):
        if not os.path.exists(path):
            continue
        cfg = read_managed_json(path)
        if cfg is None or not isinstance(cfg, dict):
            hits.append((path, None))
            continue
        found = {}
        for key in PROJECT_SANDBOX_KEYS:
            node = cfg.get("sandbox")
            for part in key:
                node = node.get(part) if isinstance(node, dict) else None
            if isinstance(node, list) and node:
                found["sandbox." + ".".join(key)] = [str(x) for x in node]
        # Claude Code builds the sandbox's write-allow set from
        # sandbox.filesystem.allowWrite AND from Edit(...) rules in
        # permissions.allow, so a repo can widen the wall without naming the
        # sandbox at all. `Edit(//abs/path/**)` becomes an absolute grant.
        allow = (cfg.get("permissions") or {}).get("allow") \
            if isinstance(cfg.get("permissions"), dict) else None
        edits = [str(r) for r in allow or [] if str(r).startswith("Edit(")]
        if edits:
            found["permissions.allow"] = edits
        if found:
            hits.append((path, found))
    return hits


def project_hooks(project_dir):
    """Settings files where the repo installs its own hooks.

    Hooks run commands outside the sandbox on every tool call, and claudex
    can't take them back either -- hook arrays merge like the rest. Refusing
    would block the many repos with legitimate hooks, so this is said out loud
    and the launch continues.
    """
    paths = []
    for path in project_settings_paths(project_dir):
        if not os.path.exists(path):
            continue
        cfg = read_managed_json(path)
        if isinstance(cfg, dict) and cfg.get("hooks"):
            paths.append(path)
    return paths


def report_project_sandbox_overrides(hits, strict, allow):
    """Print what was found; return an exit code (0 = go ahead).

    Strict has no opt-out: there the sandbox is the only thing enforcing
    `deniedDomains: ["*"]`, the secret-file denies and the env scrubbing, so
    one exempt command or one re-opened path voids the whole profile. Base can
    be overridden with CLAUDEX_ALLOW_PROJECT_SANDBOX_SETTINGS=1, but never
    silently -- the defect being worked around is that Claude Code itself says
    nothing.
    """
    for path, found in hits:
        if found is None:
            sys.stderr.write(
                "claudex: %s cannot be parsed, so its sandbox settings can't be "
                "checked\n" % path)
            continue
        for key, values in sorted(found.items()):
            sys.stderr.write(
                "claudex: %s widens the sandbox (%s): %s\n"
                % (path, key, ", ".join(values)))
    if allow and not strict:
        sys.stderr.write(
            "claudex: continuing because CLAUDEX_ALLOW_PROJECT_SANDBOX_SETTINGS=1; "
            "those commands and paths are outside the wall\n")
        return 0
    if strict and allow:
        sys.stderr.write(
            "claudex: --strict has no override for this; the sandbox is the only "
            "thing enforcing it\n")
    sys.stderr.write(
        "claudex: refusing to launch. Delete the key, or in base mode set "
        "CLAUDEX_ALLOW_PROJECT_SANDBOX_SETTINGS=1 to accept it.\n")
    return 4


def main():
    if len(sys.argv) != 4:
        sys.stderr.write(
            "usage: compose-settings.py <template.json> <trusted-roots|NONE> <out.json>\n")
        return 2
    template, roots_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

    project_dir = os.environ.get("CLAUDEX_PROJECT_DIR") or os.getcwd()
    for path in project_hooks(project_dir):
        sys.stderr.write(
            "claudex: %s installs hooks, which run outside the sandbox on every "
            "tool call\n" % path)
    hits = project_sandbox_overrides(project_dir)
    if hits:
        code = report_project_sandbox_overrides(
            hits,
            strict=os.environ.get("CLAUDEX_STRICT") == "1",
            allow=os.environ.get("CLAUDEX_ALLOW_PROJECT_SANDBOX_SETTINGS") == "1")
        if code:
            return code

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
