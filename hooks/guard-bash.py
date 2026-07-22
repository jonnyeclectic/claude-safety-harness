#!/usr/bin/env python3
"""PreToolUse safety guard for Bash under bypassPermissions.

This is the *advisory* layer. When launched via `claudex`, the OS sandbox
(Seatbelt/bubblewrap) is the hard wall that kernel-blocks subprocess writes/reads
outside the project — including tricks this regex parser can't see (python -c,
sed -i, find -delete). These hooks add fast catastrophic denies, gray-area asks,
and an out-of-workdir prompt on top, and are the only guard when NOT run via
claudex. Don't over-invest in the parser; the sandbox is the real boundary.

Decision model (kept deliberately small and auditable):
  deny  -> catastrophic / irreversible. Hard-blocked even under bypass.
  ask   -> gray-area risky ops, and any WRITE/DELETE reaching outside the
           working directory. Forces a manual-approval prompt under bypass.
  allow -> silent pass-through (print nothing) so normal bypass speed is kept.

Reads the PreToolUse payload on stdin, emits the Claude Code permission-decision
JSON on stdout. Every deny/ask is appended to ~/.claude/harness-audit.log so the
rules can be tuned from real usage.
"""
import json
import os
import re
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from harness_common import is_trusted
except Exception:  # degrade to cwd-only if the shared helper is missing
    def is_trusted(target, cwd):
        t, c = os.path.realpath(target), os.path.realpath(cwd)
        return (t == c or t.startswith(c + os.sep)
                or t.startswith(("/tmp/", "/private/tmp/", "/var/folders/", "/dev/fd/"))
                or t in {"/dev/null", "/dev/zero", "/dev/tty", "/dev/stdin",
                         "/dev/stdout", "/dev/stderr", "/dev/random", "/dev/urandom"})

AUDIT_LOG = os.path.expanduser("~/.claude/harness-audit.log")


def emit(decision, reason):
    """Print a PreToolUse permission decision and exit. allow => stay silent."""
    if decision != "allow":
        try:
            with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
                # timestamp comes from the OS, not a banned Date/random call
                fh.write(json.dumps({
                    "ts": datetime.now().isoformat(timespec="seconds"),
                    "tool": "Bash",
                    "decision": decision,
                    "reason": reason,
                    "command": CMD,
                }) + "\n")
        except OSError:
            pass  # never let logging failure block or crash the guard
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }))
    sys.exit(0)


# ---- read payload -----------------------------------------------------------
try:
    DATA = json.load(sys.stdin)
except (json.JSONDecodeError, ValueError):
    sys.exit(0)  # unparseable -> stay neutral, do not block the session

TOOL_INPUT = DATA.get("tool_input") or {}
CMD = (TOOL_INPUT.get("command") or "").strip()
CWD = DATA.get("cwd") or os.getcwd()

if not CMD:
    sys.exit(0)

low = CMD.lower()

# ---- 1. DENY: catastrophic / irreversible -----------------------------------
DENY_RULES = [
    # rm -rf whose target is the WHOLE tree: root, home, or a top-level wildcard.
    # A specific deep path outside cwd is NOT denied here -> it falls through to
    # the out-of-workdir "ask" gate below.
    (r"\brm\b(?=.*\s-[a-z]*[rf])[^\n]*?\s(/|~|~/|\$home|\$home/)\*?(\s|;|&|\||$)",
     "rm -rf targeting / ~ $HOME or a filesystem wildcard is irreversible."),
    (r"--no-preserve-root",
     "--no-preserve-root removes the last guard against wiping /."),
    # fork bomb
    (r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
     "Fork bomb detected."),
    # writing raw devices / making filesystems
    (r"\bdd\b[^\n]*\bof=/dev/(disk|rdisk|sd|nvme|hd)",
     "dd writing to a raw disk device destroys data."),
    (r"\bmkfs(\.\w+)?\b",
     "mkfs reformats a filesystem."),
    (r">\s*/dev/(disk|rdisk|sd|nvme|hd)\w*",
     "Redirecting output onto a raw disk device destroys data."),
    (r"\b(shred|wipefs)\b[^\n]*/dev/",
     "shred/wipefs on a device is irreversible."),
    # recursive chmod/chown of the whole filesystem
    (r"\bchmod\b[^\n]*-[a-z]*r[a-z]*\s+[0-7]{3,4}\s+/(\s|$)",
     "Recursive chmod on / breaks the system."),
    (r"\bchown\b[^\n]*-[a-z]*r[a-z]*\s+\S+\s+/(\s|$)",
     "Recursive chown on / breaks the system."),
]
for pat, why in DENY_RULES:
    if re.search(pat, low):
        emit("deny", f"BLOCKED by harness: {why} Command: {CMD}")

# ---- 2. ASK: gray-area risky (reversible-but-dangerous) ---------------------
GRAY_RULES = [
    (r"\bgit\s+push\b[^\n]*(--force\b|--force-with-lease\b|\s-\w*f|\s\+\S)",
     "force-push can overwrite remote history."),
    # Ask for reset --hard EXCEPT the routine "resync to an upstream/tracking
    # ref" idiom (reset --hard origin/main, @{u}, FETCH_HEAD) — those discard
    # local changes to match a ref you just fetched, which loops do constantly.
    (r"\bgit\s+reset\s+--hard\b(?!\s+(?:\S+/\S+|@\{u|fetch_head))",
     "git reset --hard to that target can discard commits/uncommitted work."),
    (r"\bgit\s+clean\s+-[a-z]*f",
     "git clean -f deletes untracked files."),
    (r"\bgit\s+commit\b[^\n]*(--no-verify|\s-\w*n)",
     "--no-verify skips the pre-commit gates."),
    (r"\bgit\s+(filter-branch|filter-repo)\b",
     "history rewrite."),
    (r"\bgit\s+rebase\b",
     "rebase rewrites commits."),
    (r"\bsudo\b",
     "sudo runs with elevated privileges."),
    (r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b",
     "piping a network download straight into a shell executes untrusted code."),
]
for pat, why in GRAY_RULES:
    if re.search(pat, low):
        emit("ask", f"Harness: gray-area op needs your OK — {why} Command: {CMD}")

# ---- 3. ASK: writes/deletes reaching outside the working directory ----------
# Heuristic: only gate MUTATING commands and file-creating redirects. Reads
# (cat/grep/ls) outside CWD pass, to keep the session fast. Relative paths are
# resolved against CWD so "./build" stays inside; absolute/home paths that land
# outside CWD -> ask for manual approval.
import shlex  # noqa: E402  (kept local to this section)

MUTATORS = ("rm", "rmdir", "mv", "cp", "install", "tee", "truncate",
            "mkdir", "touch", "ln", "chmod", "chown", "dd")


def outside_cwd(pathtok):
    """Return the resolved target if it lands outside CWD (and isn't scratch/dev),
    else None. Relative paths resolve against CWD."""
    p = pathtok.replace("${HOME}", "~").replace("$HOME", "~")
    p = os.path.expanduser(p)
    if not os.path.isabs(p):
        p = os.path.join(CWD, p)
    tgt = os.path.realpath(p)
    if is_trusted(tgt, CWD):
        return None
    return tgt


def split_statements(cmd):
    """Split a command line into top-level statements, respecting quotes, so each
    simple command is inspected on its own. Splits on ; newline | & (which also
    breaks && and ||). Quote-aware: a `python -c "...; a && b..."` blob stays one
    statement, so its contents are never mistaken for separators or for the outer
    command's arguments. This is what stops `.venv/bin/python` in a later
    statement from being read as an `rm` target of an earlier `rm -rf scratch`
    statement, and it also lets a mutator that is NOT the first word of the line
    (e.g. `cd /x && rm -rf /outside`) still be checked."""
    stmts, buf, quote = [], [], None
    for c in cmd:
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
            buf.append(c)
        elif c in ";\n|&":
            stmts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
    stmts.append("".join(buf))
    return [s.strip() for s in stmts if s.strip()]


def redirect_targets(stmt):
    """Yield the target of each real (unquoted) > or >> operator in `stmt`. A '>'
    inside quotes (e.g. the '=>' in a `python -c` code blob) is data, not a
    redirect operator, so it is ignored."""
    out, i, n, quote = [], 0, len(stmt), None
    while i < n:
        c = stmt[i]
        if quote:
            if c == quote:
                quote = None
            i += 1
        elif c in ("'", '"'):
            quote = c
            i += 1
        elif c == ">":
            i += 1
            if i < n and stmt[i] == ">":
                i += 1
            while i < n and stmt[i] in " \t":
                i += 1
            tok, tq = [], None
            while i < n:
                ch = stmt[i]
                if tq:
                    if ch == tq:
                        tq = None
                    else:
                        tok.append(ch)
                elif ch in ("'", '"'):
                    tq = ch
                elif ch in " \t\n;|&<>()`":
                    break
                else:
                    tok.append(ch)
                i += 1
            if tok:
                out.append("".join(tok))
        else:
            i += 1
    return out


for stmt in split_statements(CMD):
    # file-creating redirects (> / >>) whose target is outside CWD
    for rt in redirect_targets(stmt):
        if rt.startswith("&") or rt == "/dev/null":
            continue
        tgt = outside_cwd(rt)
        if tgt:
            emit("ask",
                 f"Harness: redirect writes outside the working directory "
                 f"({rt} -> {tgt}); approve manually. Command: {CMD}")

    # mutating command whose OWN target path is outside CWD
    try:
        tokens = shlex.split(stmt)
    except ValueError:
        tokens = stmt.split()
    if not tokens:
        continue
    cmd_word = os.path.basename(tokens[0])
    if cmd_word not in MUTATORS:
        continue
    for tok in tokens[1:]:
        if tok.startswith("-") or ("/" not in tok and not tok.startswith(("~", "$"))):
            continue
        tgt = outside_cwd(tok)
        if tgt:
            emit("ask",
                 f"Harness: {cmd_word} touches a path outside the working "
                 f"directory ({tok} -> {tgt}); approve manually. Command: {CMD}")

# ---- default: allow ---------------------------------------------------------
sys.exit(0)
