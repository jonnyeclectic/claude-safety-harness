#!/usr/bin/env python3
"""Exit 0 only if a managed-settings.json holds this repo's allow-list and
nothing else, so `uninstall.sh --managed-allowlist` knows it is safe to delete.

Managed settings are one file per machine, and a company Mac usually already
has one: hooks, MCP policy, login rules, their own sandbox denies. install.sh
refuses to overwrite it and tells you to merge the allow-list's `sandbox` block
in by hand, so the merged file is both ours and theirs. Deleting it whole would
drop their policy from every `claude` session, silently.

Two tests, because neither alone is enough. The file must carry the template's
`_installedBy` marker, which `install.sh` copies verbatim: a company's own
Claude Code allow-list has the same natural key set as ours
(`allowManagedDomainsOnly` plus `allowedDomains`), so key paths cannot tell
them apart. And it must hold no key path the template lacks -- at any depth,
`sandbox.excludedCommands` as much as a top-level `hooks` -- because the merge
advice above produces exactly that. Values are not compared: the README tells
people to edit `allowedDomains` before installing.

Usage:  is-harness-allowlist.py <managed-settings.json>

Exit 0: this repo installed it (the `_installedBy` marker), it holds nothing
        settings/managed-network-allowlist.json lacks, and the allow-list is on.
Exit 1: something else lives here; the reason goes to stderr.
Exit 2: the file (or the template) can't be read as a JSON object.
"""
import json
import os
import sys

TEMPLATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "settings", "managed-network-allowlist.json")


def read_json(path):
    """Parse the way Claude Code reads a settings file, or return None.

    It decodes a leading UTF-16LE byte-order mark as UTF-16 and anything else
    as UTF-8, then strips one leading U+FEFF. Refusing a BOM'd copy of our own
    template would tell the user their allow-list is somebody else's policy.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        text = data.decode("utf-16-le" if data.startswith(b"\xff\xfe") else "utf-8")
        if text.startswith("﻿"):
            text = text[1:]
        if not text.strip():
            return {}
        return json.loads(text)
    except (OSError, ValueError):
        return None


def key_paths(node, prefix=()):
    """Every key path in a settings object, descending into plain objects.

    Lists and scalars are leaves: what they *contain* is the user's to edit,
    what they are *called* is what identifies whose policy this is. Keys
    starting with `_` are comments, the convention this repo's templates use.
    """
    paths = set()
    for key, value in node.items():
        if key.startswith("_"):
            continue
        path = prefix + (key,)
        paths.add(path)
        if isinstance(value, dict):
            paths |= key_paths(value, path)
    return paths


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: is-harness-allowlist.py <managed-settings.json>\n")
        return 2

    cfg = read_json(sys.argv[1])
    if not isinstance(cfg, dict):
        sys.stderr.write("cannot read it as a JSON object\n")
        return 2
    template = read_json(TEMPLATE)
    if not isinstance(template, dict):
        sys.stderr.write("cannot read %s\n" % TEMPLATE)
        return 2

    marker = template.get("_installedBy")
    if cfg.get("_installedBy") != marker:
        sys.stderr.write(
            "it is not the allow-list this repo installs (no \"_installedBy\": %r); "
            "someone else's managed policy looks the same from its key names alone\n"
            % marker)
        return 1

    extra = key_paths(cfg) - key_paths(template)
    if extra:
        sys.stderr.write("it also holds: %s\n"
                         % ", ".join(sorted(".".join(p) for p in extra)))
        return 1

    sandbox = cfg.get("sandbox")
    network = sandbox.get("network") if isinstance(sandbox, dict) else None
    if not isinstance(network, dict) or network.get("allowManagedDomainsOnly") is not True:
        sys.stderr.write(
            "no allow-list here (sandbox.network.allowManagedDomainsOnly is not true)\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
