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
  ask   -> gray-area risky ops (sudo, force-push, curl|bash, rebase on a
           protected branch). Also -- only when the out-of-working-directory gate
           is enabled (HARNESS_GATE_OUTSIDE_WORKDIR=1; OFF by default) -- any
           WRITE/DELETE reaching outside the working directory. Forces a
           manual-approval prompt under bypass.
  allow -> silent pass-through (print nothing) so normal bypass speed is kept.

Reads the PreToolUse payload on stdin, emits the Claude Code permission-decision
JSON on stdout. Every deny/ask is appended to ~/.claude/harness-audit.log so the
rules can be tuned from real usage.
"""
import json
import os
import re
import shlex
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from harness_common import (is_trusted, is_scratch_root, is_temp_path,
                                outside_workdir_gate_enabled)
except Exception:  # degrade to cwd-only if the shared helper is missing
    _SCRATCH_PREFIX = ("/tmp/", "/private/tmp/", "/var/folders/",
                        "/private/var/folders/", "/dev/fd/")

    def is_trusted(target, cwd):
        t, c = os.path.realpath(target), os.path.realpath(cwd)
        return (t == c or t.startswith(c + os.sep)
                or t.startswith(_SCRATCH_PREFIX)
                or t in {"/dev/null", "/dev/zero", "/dev/tty", "/dev/stdin",
                         "/dev/stdout", "/dev/stderr", "/dev/random", "/dev/urandom"})

    def is_scratch_root(path):
        p = os.path.realpath(path)
        return p.startswith(_SCRATCH_PREFIX)

    def is_temp_path(path):
        return os.path.realpath(path).startswith(_SCRATCH_PREFIX)

    def outside_workdir_gate_enabled():
        return os.environ.get("HARNESS_GATE_OUTSIDE_WORKDIR", "").strip().lower() in (
            "1", "true", "yes", "on")

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

# ---- scan text: match DENY/GRAY patterns against CODE, not DATA --------------
# The rules below pattern-match the command string. A heredoc body
# (`git commit -F - <<'EOF' ... EOF`, `cat <<'EOF' ... EOF`) and a quoted
# argument (`git commit -m "..."`, `echo "..."`) are DATA handed to a command,
# not shell the shell executes -- yet a naive scan flags dangerous-looking WORDS
# inside them (a commit message that says "rm -rf /" is not a delete).
# code_only() blanks that literal data before matching but KEEPS anything that
# is still executed: an interpreter's arg/stdin (`bash -c "..."`, `python
# <<EOF`, `eval "..."`) AND command substitutions, which run even in data
# position -- `"$(cmd)"`, `` "`cmd`" ``, and `$(...)` in an unquoted heredoc
# body. Single-quoted data and quoted-delimiter heredocs are truly literal and
# stay blanked. It errs toward KEEPING text on any doubt: the worst case is an
# over-broad match (a spurious ask), never a missed catastrophic command. Path
# logic (sections' cd-tracking / out-of-cwd checks) still works on the raw
# command via _strip_heredocs so real targets are never blanked.

# Commands that execute a string arg or their stdin as code. If one appears as
# a bare word in a statement, that statement's quotes/heredoc are CODE and stay
# in the scan; otherwise they are data and get blanked.
_INTERP = {"sh", "bash", "zsh", "ksh", "dash", "ash", "csh", "tcsh", "fish",
           "python", "python2", "python3", "perl", "ruby", "node", "eval",
           "source"}

# Commands whose quoted operands are the very PATHS the catastrophic DENY rules
# in section 1 test, so their quotes must survive the scan exactly as an
# interpreter's do. Blanking quoted data is right for a command that only PRINTS
# or RECORDS it (`echo`, `git commit -m`) -- but `rm -rf "/"` and
# `rm -rf "$HOME"` are the way these are actually written, and treating those
# operands as inert data made the whole-tree rules miss the quoted form
# entirely. Keeping them costs nothing: a target that is merely a specific path
# (`rm -rf "$HOME/.cache"`) still fails the whole-tree rules on its own.
_TARGET_CMDS = {"rm", "chmod", "chown", "dd", "shred", "wipefs"}

# Either kind of word makes the rest of its statement's quotes CODE, not data.
_KEEP_QUOTED = _INTERP | _TARGET_CMDS


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


def _has_interp(text):
    """True if `text` invokes a shell/interpreter as a bare word -- meaning its
    quoted args / heredoc body are executed and must stay in the scan. Tokens
    are split BEFORE the membership test, so an interpreter name that only
    appears INSIDE a quoted string (the word "bash" in a commit message) is one
    token and does not count."""
    try:
        toks = shlex.split(text, posix=False)
    except ValueError:
        toks = text.split()
    return any(os.path.basename(t) in _INTERP for t in toks)


def _keep_substitutions(data):
    """Blank the LITERAL characters of a data string but PRESERVE command-
    substitution spans -- `$(...)` (paren-nested) and `` `...` `` -- because the
    shell still EXECUTES those even when the surrounding text is data: inside
    double quotes (`"...$(cmd)..."`) and inside an UNQUOTED heredoc body. Only
    single-quoted data and QUOTED-delimiter heredoc bodies are truly literal,
    and those never reach here. Whitespace/newlines are kept so statement and
    line boundaries survive for the scanners; every other literal char is
    dropped so a scary WORD that is merely data does not match."""
    out, i, n = [], 0, len(data)
    while i < n:
        c = data[i]
        if c == "$" and i + 1 < n and data[i + 1] == "(":
            out.append("$(")
            i += 2
            depth = 1
            while i < n and depth:
                ch = data[i]
                out.append(ch)
                i += 1
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
        elif c == "`":
            out.append(c)
            i += 1
            while i < n and data[i] != "`":
                out.append(data[i])
                i += 1
            if i < n:
                out.append("`")  # closing backtick
                i += 1
        elif c in " \t\n":
            out.append(c)  # keep structural whitespace
            i += 1
        else:
            i += 1  # blank a literal data character
    return "".join(out)


def _strip_heredocs(cmd):
    """Reduce heredoc BODIES to the CODE the shell runs, keeping each opener and
    closing-delimiter line. Three cases by receiver/delimiter:
      - opener runs an interpreter (`bash <<EOF ... EOF`): the whole body is
        executed -> kept and still scanned;
      - non-interpreter, QUOTED delimiter (`cat <<'EOF' ... EOF`): the body is
        fully literal stdin data -> dropped;
      - non-interpreter, UNQUOTED delimiter (`cat <<EOF ... EOF`): the body is
        stdin data BUT still undergoes command substitution -> only its
        `$(...)`/backtick spans are kept (via _keep_substitutions), so a real
        payload is caught while literal scary words are dropped."""
    opener = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")
    lines, out, i = cmd.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = opener.search(line)
        if m:
            delim = m.group(2)
            keep_all = _has_interp(line)          # interpreter executes the body
            subst_only = not keep_all and not m.group(1)  # unquoted non-interp
            i += 1
            while i < len(lines) and lines[i].strip() != delim:
                if keep_all:
                    out.append(lines[i])
                elif subst_only:
                    out.append(_keep_substitutions(lines[i]))
                i += 1
            if i < len(lines):
                out.append(lines[i])  # the closing delimiter line itself
        i += 1
    return "\n".join(out)


def code_only(cmd):
    """`cmd` reduced to the text the shell executes as CODE: heredoc bodies and
    quoted-argument contents removed, EXCEPT where they are still executed or are
    a path a DENY rule must see. Structural characters (separators, pipes,
    redirects, quote marks) are kept, so e.g. the `|` in `curl x | sh` survives
    for the pipe-into-shell rule.

    Three quote contexts:
      - arg of a _KEEP_QUOTED command: either an interpreter (`bash -c "..."`,
        `eval "..."`), where the whole quoted string is executed, or a
        _TARGET_CMDS path operand (`rm -rf "/"`), where it is the target the
        catastrophic rules check -> kept verbatim either way;
      - single-quoted data (`'...'`): the shell suppresses ALL expansion ->
        fully literal -> blanked;
      - double-quoted data (`"..."`): word-splitting is suppressed but command
        substitution is NOT -- `"$(cmd)"` and `` "`cmd`" `` still run -> the
        literal text is blanked but the `$(...)`/backtick spans are KEPT
        (via _keep_substitutions), so a real payload is still caught.

    Single pass: the command word of a statement precedes its quoted args, so
    tracking the words seen so far in the current statement is enough to know,
    at the moment a quote opens, whether its contents are code (keep) or data
    (blank/substitution-only). Words are only accumulated OUTSIDE quotes, so an
    `rm` or `bash` appearing inside a message string never flips its own
    statement into keep-mode."""
    text = _strip_heredocs(cmd)
    out, word, quote, keep_quoted = [], [], None, False
    dq = []  # buffer of double-quoted DATA awaiting substitution-aware blanking

    def flush_word():
        nonlocal keep_quoted
        if word:
            if os.path.basename("".join(word)) in _KEEP_QUOTED:
                keep_quoted = True
            del word[:]

    for c in text:
        if quote:
            if keep_quoted:           # executed code, or a path operand we test
                out.append(c)
                if c == quote:
                    quote = None
            elif quote == "'":        # single quotes: fully literal data
                if c == quote:
                    quote = None
                    out.append(c)     # keep the closing quote mark
                # else: blank the quoted data character
            else:                     # double quotes: data, but $()/`` execute
                if c == quote:
                    out.append(_keep_substitutions("".join(dq)))
                    del dq[:]
                    quote = None
                    out.append(c)     # keep the closing quote mark
                else:
                    dq.append(c)
            continue
        if c in ("'", '"'):
            flush_word()
            quote = c
            out.append(c)         # keep the opening quote mark
        elif c in ";\n|&":
            flush_word()
            keep_quoted = False   # new statement -> reset the keep-quotes context
            out.append(c)
        elif c in " \t":
            flush_word()
            out.append(c)
        else:
            word.append(c)
            out.append(c)
    if dq:  # unterminated double quote -> err toward keeping (scan what's there)
        out.append(_keep_substitutions("".join(dq)))
    return "".join(out)


low = code_only(CMD).lower()
# The same scan text with quote MARKS removed, used by the whole-filesystem
# target rules in section 1. code_only deliberately keeps the marks (and, for a
# _TARGET_CMDS word, the quoted operand itself) -- that is what lets `rm -rf "/"`
# be seen at all. But a mark is NOT a reliable end-of-target boundary, because a
# single path can be quoted in pieces: `"$HOME"/.cache/foo` is one specific
# subpath, not a home wipe, yet its target looks finished at the closing quote.
# Dropping the marks renormalizes every spelling -- `"/"`, `"$HOME"`, `"$HOME"/`,
# `"$HOME"/.cache` -- to the bare form the boundary rules are written against,
# so they need no quote cases at all. Only section 1 uses this; the gray-area
# rules keep the quote-preserving `low`.
low_paths = low.replace('"', "").replace("'", "")

def redirect_targets(stmt):
    """Yield the target of each real (unquoted) > or >> operator in `stmt`, with
    any quotes around it stripped. A '>' inside quotes (e.g. the '=>' in a
    `python -c` code blob) is data, not a redirect operator, so it is ignored.

    Defined here, above section 1, because a redirect target is a path the SHELL
    writes to no matter which command runs -- so the raw-device DENY needs it
    too, not just the out-of-workdir ask in section 3.
    """
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


# ---- 1. DENY: catastrophic / irreversible -----------------------------------
# Trailing boundary for a whole-filesystem target. Beyond the usual whitespace /
# statement separators, `)` and backtick count as boundaries too: code_only()
# KEEPS command-substitution spans (they execute even in data position), so a
# target inside `"$(...)"` or `` "`...`" `` reaches the scanner as e.g.
# `rm -rf /)` -- without `)`/backtick here the trailing char would stop the
# target rule from matching and a real wipe/format would slip through.
# These rules run against low_paths (quote marks stripped), so a quoted target
# arrives in the same bare form as an unquoted one and needs no cases here.
_END = r"(?:\s|[;&|)`]|$)"
DENY_RULES = [
    # rm -rf whose target is the WHOLE tree: root, home, or a top-level wildcard.
    # `$home` covers both spellings code_only can produce (`$HOME`, `${HOME}`),
    # each with or without a trailing slash. A specific deep path outside cwd is
    # NOT denied here (`~/.cache` fails the boundary) -> it falls through to the
    # out-of-workdir "ask" gate below.
    (r"\brm\b(?=.*\s-[a-z]*[rf])[^\n]*?\s(/|~/?|\$\{?home\}?/?)\*?" + _END,
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
    # NB: redirecting ONTO a raw device is denied separately, on the parsed
    # statements rather than the scan text -- see _RAW_DEVICE below.
    (r"\b(shred|wipefs)\b[^\n]*/dev/",
     "shred/wipefs on a device is irreversible."),
    # recursive chmod/chown of the whole filesystem
    (r"\bchmod\b[^\n]*-[a-z]*r[a-z]*\s+[0-7]{3,4}\s+/" + _END,
     "Recursive chmod on / breaks the system."),
    (r"\bchown\b[^\n]*-[a-z]*r[a-z]*\s+\S+\s+/" + _END,
     "Recursive chown on / breaks the system."),
]
# These rules FIRE below, after the assignment / effective-cwd walk is built, so
# the whole-tree rm rule (index 0) can resolve what `~`/`$HOME` actually point at
# -- a HOME reassigned on the SAME command line
# (`export HOME="$TMPDIR/x" && rm -rf "$HOME"`), or an ambient HOME that is
# already a temp dir -- instead of always reading them as the user's real home.
# See _rm_home_targets_disposable_home.

# ---- helpers: script-local var tracking + statement/effective-cwd walk -----
# Split into statements once and track two things across them, in order, so
# a LATER statement sees what an EARLIER one in the SAME command line set up:
#   ASSIGNS    -- vars this command line itself export/assigned (see
#                 expand_vars/record_assignments) so $HOME after an
#                 `export HOME=/tmp/x` resolves to /tmp/x, not the hook
#                 process's own environment.
#   STMT_CWDS  -- the effective directory in scope at each statement, updated
#                 by any `cd <path>` statement. Needed because the hook only
#                 gets the SESSION's cwd (DATA["cwd"]) -- a command that does
#                 `cd /tmp/loop && git rebase ...` runs the rebase in
#                 /tmp/loop, not the session's cwd, so location-based checks
#                 (is_scratch_root below, and the outside-cwd gate in
#                 section 3) must track that shift, not just trust the
#                 payload cwd.
ASSIGNS = {}
_ASSIGN_WORD = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
_VAR_REF = re.compile(r"\$\{(\w+)\}|\$(\w+)")


def _unquote(raw):
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    return raw


def expand_vars(s, assigns):
    """Substitute $NAME / ${NAME} against `assigns` (what THIS command line has
    itself export/assigned so far, e.g. `export HOME=/tmp/x`) before falling
    back to the hook process's own environment. Unknown vars are left as-is
    (e.g. $(cmd) substitutions, which this parser doesn't attempt)."""
    def repl(m):
        name = m.group(1) or m.group(2)
        if name in assigns:
            return assigns[name]
        return os.environ.get(name, m.group(0))
    return _VAR_REF.sub(repl, s)


def record_assignments(stmt, assigns):
    """If `stmt` is `[export] NAME=val [NAME2=val2 ...]`, record each NAME ->
    val into `assigns` (quote-aware, resolving refs to vars already known)
    so a LATER statement's $NAME resolves against what this command line
    itself set -- not the hook process's own environment. This is what makes
    e.g. `export HOME=/tmp/x; mkdir -p "$HOME"` recognized as writing inside
    /tmp rather than the real $HOME. Stops at the first non-assignment word,
    so plain commands (mkdir, rm, ...) and `FOO=bar cmd args` are untouched."""
    try:
        words = shlex.split(stmt, posix=False)
    except ValueError:
        return
    if words and words[0] == "export":
        words = words[1:]
    for w in words:
        m = _ASSIGN_WORD.match(w)
        if not m:
            break
        assigns[m.group(1)] = expand_vars(_unquote(m.group(2)), assigns)


def resolve_path(pathtok, assigns, base):
    """Expand $VAR/~ (against `assigns`, i.e. this command line's own
    export/assignments, falling back to the hook's own env) and resolve a
    relative path against `base`. Shared by outside_cwd() and the `cd`-
    tracking walk below so both use identical expansion rules."""
    p = expand_vars(pathtok, assigns)
    if p == "~" or p.startswith("~/"):
        home = assigns.get("HOME") or os.environ.get("HOME")
        if home:
            p = home + p[1:]
    p = os.path.expanduser(p)
    if not os.path.isabs(p):
        p = os.path.join(base, p)
    return os.path.realpath(p)


def outside_cwd(pathtok, base):
    """Return the resolved target if it lands outside `base` (and isn't
    scratch/dev/trusted), else None."""
    tgt = resolve_path(pathtok, ASSIGNS, base)
    if is_trusted(tgt, base):
        return None
    return tgt


def _checkout_branch(toks):
    """If `toks` is a `git checkout`/`git switch` that lands on a branch, return
    that branch name, else None. Handles `-b`/`-B`/`-c`/`-C NEWBRANCH` (create +
    switch) and a plain `checkout <branch>`. A `checkout -- <file>` returns None;
    a pathspec checkout may return the token, but that only ever reads as a
    non-protected name (-> allowed), so misreading a file as a branch never
    suppresses a real protected-branch prompt. Used to track which branch a
    later `git rebase` on the same command line would rewrite."""
    if len(toks) < 3 or os.path.basename(toks[0]) != "git":
        return None
    if toks[1] not in ("checkout", "switch"):
        return None
    rest = toks[2:]
    for i, t in enumerate(rest):
        if t in ("-b", "-B", "-c", "-C") and i + 1 < len(rest):
            return rest[i + 1]
    for t in rest:
        if t == "--":
            break
        if t.startswith("-"):
            continue
        return t
    return None


# Heredoc bodies are stripped first: for a non-interpreter receiver they are
# stdin data, not executed, so a `mkdir /outside` or `cd /elsewhere` inside one
# must not drive the cd-tracking or out-of-cwd checks. A `bash <<EOF` body IS
# kept (see _strip_heredocs) and so is still walked.
STATEMENTS = split_statements(_strip_heredocs(CMD))
STMT_CWDS = []  # effective cwd in scope at each statement, same order
STMT_BRANCHES = []  # effective checked-out branch at each statement (None=unknown)
_eff_cwd = os.path.realpath(CWD)
_eff_branch = None  # the hook is not told the session's current branch
for _stmt in STATEMENTS:
    record_assignments(_stmt, ASSIGNS)
    STMT_CWDS.append(_eff_cwd)
    STMT_BRANCHES.append(_eff_branch)  # branch in scope BEFORE this stmt's checkout
    try:
        _toks = shlex.split(_stmt)
    except ValueError:
        _toks = _stmt.split()
    if _toks and _toks[0] == "cd":
        _target = _toks[1] if len(_toks) > 1 else "~"
        if _target != "-":  # `cd -` (previous dir): not tracked, don't guess
            _eff_cwd = resolve_path(_target, ASSIGNS, _eff_cwd)
    _br = _checkout_branch(_toks)
    if _br is not None:
        _eff_branch = _br


# ---- 1 (fired): DENY, now that ASSIGNS / STATEMENTS / STMT_CWDS exist --------
def _home_is_disposable():
    """Whether the HOME that this line's `~`/`$HOME` actually resolve to is a
    throwaway home rather than the user's real one. Two ways it can be:

      - the command line ITSELF reassigned it (`export HOME=...`, or a
        `HOME=... rm` prefix). The target is then checked per-rm below, so the
        reassignment alone is enough to enter the rescue -- a reassignment to a
        NON-scratch dir is rejected there, not here.
      - it was ALREADY a temp dir in the ambient environment -- the session runs
        under a throwaway home (test isolation, CI, a container, a sandboxed
        run), so `~` means /tmp/... or $TMPDIR/... for every command, not just
        ones that re-export it. is_temp_path, not is_scratch_root: a configured
        trusted root is a place the owner KEEPS things, so a home living there
        is a real home and its wipe stays denied."""
    if "HOME" in ASSIGNS:
        return True
    ambient = os.environ.get("HOME")
    return bool(ambient) and is_temp_path(ambient)


def _rm_home_targets_disposable_home():
    """The whole-tree rm DENY (DENY_RULES[0]) is a FALSE POSITIVE when `~`/`$HOME`
    do not mean the user's real home -- either because the command line itself
    retargeted HOME to a throwaway path (the routine
    `export HOME="$TMPDIR/x" && rm -rf "$HOME"` test-isolation idiom) or because
    the session already runs under a temp HOME (see _home_is_disposable).

    Return True (suppress the deny) only when HOME is disposable AND every
    recursive-rm statement targets ONLY safe paths: a `~`/`$HOME` that resolves
    into a scratch/trusted dir (rescued), or a specific non-root path. A literal
    `/`, a root wildcard, or a home ref that resolves OUTSIDE scratch returns
    False so the catastrophic deny stands. Conservative by construction: an
    ambient home that is NOT temp, an rm hidden in a substitution (no top-level
    rm statement to rescue), or any parse doubt all leave the deny in place."""
    if not _home_is_disposable():
        return False                  # real home -> a real-home wipe -> deny
    rescued = False
    for _s, _base in zip(STATEMENTS, STMT_CWDS):
        try:
            # POSIX mode (unlike the posix=False splits elsewhere in this file):
            # it strips the quote marks and, crucially, JOINS the pieces of a
            # word the way the shell does. Non-POSIX mode breaks at the closing
            # quote, turning `rm -rf "$HOME"/` into the two tokens `"$HOME"` and
            # `/` -- and that bare `/` reads as a whole-root wipe, which would
            # keep the deny on exactly the command this rescue exists for.
            _rtoks = shlex.split(_s)
        except ValueError:
            return False
        # step past a leading `export` and any NAME=val prefix assignments
        if _rtoks and _rtoks[0] == "export":
            _rtoks = _rtoks[1:]
        while _rtoks and _ASSIGN_WORD.match(_rtoks[0]):
            _rtoks = _rtoks[1:]
        if not _rtoks or os.path.basename(_rtoks[0]) != "rm":
            continue
        _args = _rtoks[1:]
        if not any(t.startswith("-") and not t.startswith("--")
                   and "r" in t.lower() for t in _args):
            continue                  # non-recursive rm cannot wipe a tree
        for _tok in _args:
            if _tok.startswith("-"):
                continue
            _core = _tok
            if _core.endswith("/*"):
                _core = _core[:-2]
            elif _core.endswith("/") and len(_core) > 1:
                _core = _core[:-1]
            if _core in ("", "/"):
                return False          # whole-root target -> keep the deny
            if _core in ("~", "$HOME", "${HOME}"):
                _tgt = resolve_path(_core, ASSIGNS, _base)
                if is_scratch_root(_tgt) or is_trusted(_tgt, _base):
                    rescued = True     # the home in effect points at scratch
                else:
                    return False       # a home, but not a throwaway one
    return rescued


for _i, (_pat, _why) in enumerate(DENY_RULES):
    if re.search(_pat, low_paths):
        if _i == 0 and _rm_home_targets_disposable_home():
            continue                  # throwaway HOME -> not the real home
        emit("deny", f"BLOCKED by harness: {_why} Command: {CMD}")

# Redirect ONTO a raw disk device -- checked on the parsed statements, not the
# scan text. The target of `> "/dev/rdisk0"` is a path the shell writes to
# whatever the command is, but for a command that merely prints its argument
# (`echo`, and every other non-_KEEP_QUOTED word) code_only correctly blanks the
# quoted target as data before the regex rules ever see it. redirect_targets()
# extracts exactly that operand, quotes stripped, so the quoted spelling is
# caught without keeping every quoted argument of every command in the scan.
_RAW_DEVICE = re.compile(r"^/dev/(disk|rdisk|sd|nvme|hd)\w*$")
for _stmt in STATEMENTS:
    for _rt in redirect_targets(_stmt):
        if _RAW_DEVICE.match(expand_vars(_rt, ASSIGNS)):
            emit("deny", "BLOCKED by harness: Redirecting output onto a raw disk "
                         f"device destroys data. Command: {CMD}")

# Branches whose force-push is a real, everyone-affecting history overwrite.
# Force-pushing any OTHER explicit branch is the routine amend->force-push
# topic/PR-branch idiom and is allowed.
_PROTECTED_BRANCHES = {"main", "master", "develop", "trunk"}


def force_push_asks(stmt):
    """True if `stmt` is a `git push` FORCE that should ASK. A force-push whose
    every destination ref is an explicit non-protected branch (updating your own
    topic/PR branch) is allowed; a force-push to a default/shared branch
    (main/master/...), an --all/--mirror push, or a force-push with no explicit
    branch (target unknown -> could be the default branch) still asks -- that is
    where an irreversible shared-history overwrite lives. Tokens are shlex-split,
    so a `git push --force ...` mentioned inside a QUOTED commit message is one
    token, not a command, and never trips this."""
    try:
        toks = shlex.split(stmt, posix=False)
    except ValueError:
        return False
    low_toks = [t.lower() for t in toks]
    if "push" not in low_toks:
        return False
    pi = low_toks.index("push")
    if pi == 0 or os.path.basename(low_toks[pi - 1]) != "git":
        return False
    after = toks[pi + 1:]

    def _is_force_flag(t):
        return (t in ("--force", "--force-with-lease")
                or t.startswith("--force-with-lease=")
                or (t.startswith("-") and not t.startswith("--")
                    and "f" in t[1:].lower()))

    forced = (any(_is_force_flag(t) for t in after)
              or any(t.startswith("+") and len(t) > 1 for t in after))
    if not forced:
        return False
    if any(t.lower() in ("--all", "--mirror") for t in after):
        return True  # pushes many/all refs -> ask
    # positional args after `push` are [remote, refspec...]; drop flags and any
    # redirect/control token (`2>&1`, `>log`) so only real refspecs remain.
    positional = [t for t in after
                  if not t.startswith("-") and not any(c in t for c in "<>&")]
    refspecs = positional[1:]  # first positional is the remote (name or URL)
    if not refspecs:
        return True  # no explicit branch -> target unknown -> ask
    for spec in refspecs:
        dst = spec.split(":")[-1].lstrip("+")   # `src:dst`/`+dst` -> dst
        if dst.lower().startswith("refs/heads/"):
            dst = dst[len("refs/heads/"):]
        dst = dst.lower()
        if not dst or "*" in dst or dst in _PROTECTED_BRANCHES:
            return True  # protected / glob / empty (deletion) -> ask
    return False  # every destination is an explicit non-protected branch


# ---- 2. ASK: gray-area risky (reversible-but-dangerous) ---------------------
# GLOBAL: blast radius reaches beyond the directory the command runs in (a
# real remote, elevated privileges, arbitrary code exec) -- ask regardless of
# location, scratch clone or not.
GRAY_RULES_GLOBAL = [
    (r"\bsudo\b",
     "sudo runs with elevated privileges."),
    (r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b",
     "piping a network download straight into a shell executes untrusted code."),
]
for pat, why in GRAY_RULES_GLOBAL:
    if re.search(pat, low):
        emit("ask", f"Harness: gray-area op needs your OK — {why} Command: {CMD}")

# force-push: ask only where a real shared-history overwrite can happen -- a
# default/protected branch, an --all/--mirror push, or a push with no explicit
# branch (target unknown). A force-push to an explicit non-protected branch (the
# routine amend->force-push topic/PR-branch idiom) is allowed. Per-STATEMENT so
# `cd /x && git push -f ...` is still seen; location-independent (a real remote
# is reached from any cwd, scratch clone or not).
for _stmt in STATEMENTS:
    if force_push_asks(_stmt):
        emit("ask",
             "Harness: gray-area op needs your OK — force-push to a default/"
             f"shared branch or all refs can overwrite remote history. "
             f"Command: {CMD}")

# LOCAL: git history-rewrite ops whose blast radius is confined to the repo
# they run in. Skip the prompt when that repo's effective directory is
# scratch/trusted (is_scratch_root) -- the same trust boundary the location
# gate already uses in section 3, applied here because rewriting history in a
# throwaway loop/remediation clone is exactly as disposable as any other
# write there would be. Checked per-STATEMENT against that statement's own
# effective cwd (STMT_CWDS from the walk above), so
# `cd /tmp/loop && git rebase ...` is recognized as scratch even though the
# session's own cwd is the real project directory.
GRAY_RULES_LOCAL = [
    (r"\bgit\s+reset\s+--hard\b(?!\s+(?:\S+/\S+|@\{u|fetch_head))",
     "git reset --hard to that target can discard commits/uncommitted work."),
    (r"\bgit\s+clean\s+-[a-z]*f",
     "git clean -f deletes untracked files."),
    (r"\bgit\s+(filter-branch|filter-repo)\b",
     "history rewrite."),
]
# `git rebase` is handled separately (below): unlike the rules above it is LOCAL
# and reflog-recoverable, and its one irreversible SHARED step -- force-pushing
# the result -- is gated on its own (force_push_asks). So it asks only when it
# rewrites a PROTECTED branch's history, not for the routine topic-branch rebase.
# NB: `git commit --no-verify` / `-n` is deliberately NOT gated. Every rule
# above can destroy committed or uncommitted WORK; --no-verify destroys nothing
# and touches nothing outside the repo -- it only skips optional pre-commit
# hooks, a code-quality concern, not the catastrophic/outward-facing threat this
# advisory layer exists for. Gating it just stalled routine automated commits
# (agent loops use it constantly) with no safety return.
for _stmt, _stmt_cwd, _stmt_branch in zip(STATEMENTS, STMT_CWDS, STMT_BRANCHES):
    if is_scratch_root(_stmt_cwd):
        continue  # disposable loop/remediation clone -> skip local-rewrite prompts
    _low_stmt = code_only(_stmt).lower()  # don't match a git verb inside a message
    for pat, why in GRAY_RULES_LOCAL:
        if re.search(pat, _low_stmt):
            emit("ask",
                 f"Harness: gray-area op needs your OK — {why} Command: {CMD}")
    # git rebase: ask only when the effective checked-out branch (tracked from a
    # `git checkout`/`switch` earlier on this command line) is a PROTECTED branch,
    # i.e. the rebase would rewrite main/master/develop/trunk history. Rebasing a
    # topic branch onto an updated main, or a standalone `git rebase <upstream>`
    # whose branch we cannot see, is the routine idiom and is allowed.
    if (re.search(r"\bgit\s+rebase\b", _low_stmt)
            and _stmt_branch is not None
            and _stmt_branch.lower() in _PROTECTED_BRANCHES):
        emit("ask",
             "Harness: gray-area op needs your OK — rebase rewrites the history "
             f"of protected branch '{_stmt_branch}'. Command: {CMD}")

# ---- 3. ASK: writes/deletes reaching outside the working directory ----------
# OFF by default (outside_workdir_gate_enabled() -> False): the owner relaxed the
# location gate so file writes/creates/deletes anywhere -- git worktrees, sibling
# dirs, scaffolding -- pass without a prompt. Set HARNESS_GATE_OUTSIDE_WORKDIR=1
# to re-enable. When on: only MUTATING commands and file-creating redirects are
# gated; reads (cat/grep/ls) outside cwd pass, to keep the session fast. Relative
# paths resolve against each statement's own effective cwd (STMT_CWDS, from the
# walk above) so "./build" after a `cd` stays recognized as inside; absolute/home
# paths that land outside -> ask for manual approval. (Catastrophic denies in
# section 1 and the gray-area asks in section 2 fire regardless of this gate.)
MUTATORS = ("rm", "rmdir", "mv", "cp", "install", "tee", "truncate",
            "mkdir", "touch", "ln", "chmod", "chown", "dd")

# Mutators that READ their leading operand(s) and WRITE only the final one:
# `cp`/`install` copy FROM source(s) INTO a destination, `ln` links a target
# name into a new link. Reads outside cwd are fine (see the section header), so
# only the DESTINATION is a real out-of-cwd write worth gating -- otherwise
# `cp "$HOME/.cache/x" "$TMPDIR/y"` asks for the source it merely reads. `mv` is
# deliberately excluded: it REMOVES its sources, so an out-of-cwd source there is
# a genuine mutation and stays gated.
COPY_LIKE = {"cp", "install", "ln"}


def write_targets(cmd_word, tokens):
    """The path operands a mutator actually WRITES/REMOVES -- the ones worth
    gating against the out-of-cwd rule. For a COPY_LIKE command that is only the
    destination: the value of `-t`/`--target-directory` if present, else the last
    non-flag operand (its leading operands are read sources). For every other
    mutator, all operands are targets."""
    operands = tokens[1:]
    if cmd_word not in COPY_LIKE:
        return operands
    for i, t in enumerate(operands):
        if t in ("-t", "--target-directory") and i + 1 < len(operands):
            return [operands[i + 1]]
        if t.startswith("--target-directory="):
            return [t.split("=", 1)[1]]
    positional = [t for t in operands if not t.startswith("-")]
    return positional[-1:]  # the destination only (empty if no operands)


if outside_workdir_gate_enabled():
    for stmt, stmt_cwd in zip(STATEMENTS, STMT_CWDS):
        # file-creating redirects (> / >>) whose target is outside this
        # statement's effective cwd
        for rt in redirect_targets(stmt):
            if rt.startswith("&") or rt == "/dev/null":
                continue
            tgt = outside_cwd(rt, stmt_cwd)
            if tgt:
                emit("ask",
                     f"Harness: redirect writes outside the working directory "
                     f"({rt} -> {tgt}); approve manually. Command: {CMD}")

        # mutating command whose OWN target path is outside this statement's
        # effective cwd
        try:
            tokens = shlex.split(stmt)
        except ValueError:
            tokens = stmt.split()
        if not tokens:
            continue
        cmd_word = os.path.basename(tokens[0])
        if cmd_word not in MUTATORS:
            continue
        for tok in write_targets(cmd_word, tokens):
            if tok.startswith("-") or ("/" not in tok
                                       and not tok.startswith(("~", "$"))):
                continue
            tgt = outside_cwd(tok, stmt_cwd)
            if tgt:
                emit("ask",
                     f"Harness: {cmd_word} writes to a path outside the working "
                     f"directory ({tok} -> {tgt}); approve manually. Command: {CMD}")

# ---- default: allow ---------------------------------------------------------
sys.exit(0)
