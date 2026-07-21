#!/usr/bin/env python3
"""PreToolUse guard for file-editing tools under bypassPermissions.

Any Edit/Write/MultiEdit/NotebookEdit whose target file resolves OUTSIDE the
working directory is deferred to manual approval (ask). Edits inside the workdir
pass silently, preserving bypass speed. This is the file-tool half of the
"manual approval for interactions outside the working directory" rule; the Bash
half lives in guard-bash.py.

Why this still matters alongside the OS sandbox: the Claude Code sandbox only
wraps Bash subprocesses — the built-in Read/Edit/Write tools are NOT sandboxed,
so this hook is the boundary for those tools even under `claudex`.
"""
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from harness_common import is_trusted
except Exception:  # degrade to cwd-only if the shared helper is missing
    def is_trusted(target, cwd):
        t, c = os.path.realpath(target), os.path.realpath(cwd)
        return (t == c or t.startswith(c + os.sep)
                or t.startswith(("/tmp/", "/private/tmp/", "/var/folders/")))

AUDIT_LOG = os.path.expanduser("~/.claude/harness-audit.log")


def emit(decision, reason, tool, path):
    if decision != "allow":
        try:
            with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "ts": datetime.now().isoformat(timespec="seconds"),
                    "tool": tool,
                    "decision": decision,
                    "reason": reason,
                    "path": path,
                }) + "\n")
        except OSError:
            pass
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }))
    sys.exit(0)


try:
    DATA = json.load(sys.stdin)
except (json.JSONDecodeError, ValueError):
    sys.exit(0)

TOOL = DATA.get("tool_name", "")
TOOL_INPUT = DATA.get("tool_input") or {}
CWD = DATA.get("cwd") or os.getcwd()

# file path key differs slightly across tools; cover the known ones
path = (TOOL_INPUT.get("file_path")
        or TOOL_INPUT.get("notebook_path")
        or TOOL_INPUT.get("path")
        or "")
if not path:
    sys.exit(0)

target = os.path.realpath(os.path.expanduser(path))

if is_trusted(target, CWD):
    sys.exit(0)  # inside the workdir / a trusted root / scratch -> allow silently

emit("ask",
     f"Harness: {TOOL} targets a file outside the working directory "
     f"({target}); approve manually.",
     TOOL, target)
