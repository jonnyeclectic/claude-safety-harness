#!/usr/bin/env python3
"""Stop hook: nudge to run the project's tests before finishing.

Fires when the session is wrapping up. If a CODE file inside the working
directory was modified and NO test/check command ran afterward, it blocks the
stop once with a reason telling Claude to verify functionality is preserved by
running the project's test command (auto-detected: make check/test, pytest, npm
test, cargo test, go test, ...). Stays silent for Q&A / docs-only / config-or-
data-only / already-tested sessions.

It nudges ONCE per set of untested edits. `stop_hook_active` alone is not
enough: that flag only silences the immediate re-block, so once an untested
edit existed the nudge re-fired at every LATER stop for the rest of the
session (64 times in one observed session, because the project's real suite
-- ./bin/check.sh -- was not recognised as a test run, so the condition could
never clear). The durable guard is the transcript itself: a nudge we already
delivered is visible in it, and suppresses the next one until new code is
edited.
"""
import json
import os
import re
import sys

# Extensions whose edits a test run would actually exercise. The nudge exists to
# verify CODE still works, so it fires ONLY for these -- never for docs, config,
# data, lockfiles, CI yaml, or dotfiles like .gitignore. Those used to count as
# "source" (anything not a doc did), so touching one LAST -- e.g. a trailing
# .gitignore tweak after the real code was already tested -- spuriously re-fired
# the nag. An allowlist also means the worst case is a missed reminder (cheap),
# never a false block (friction), which is the right bias for an advisory hook.
CODE_EXT = (
    ".py", ".pyi", ".pyx",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
    ".go", ".rs", ".rb", ".java", ".kt", ".kts", ".scala", ".groovy", ".clj",
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".cs",
    ".swift", ".m", ".mm", ".php", ".pl", ".pm",
    ".ex", ".exs", ".erl", ".hs", ".ml", ".fs", ".dart", ".lua",
    ".sh", ".bash", ".zsh", ".sql", ".r", ".jl",
)

# A project-local runner invoked as a script: ./bin/check.sh, bash bin/check.sh,
# ./scripts/test.sh, ./run-tests.sh. Anchored on INVOCATION position -- start of
# command, after a separator/newline, or behind an explicit interpreter -- so a
# writability probe like `echo test > f` and a syntax-only lint like
# `bash -n bin/check.sh` (the path is an argument there, not the command) stay
# out. These are the suites that repos without a Makefile or package.json
# actually use, and missing them is what made the nudge unclearable.
PROJECT_TEST_RUN = re.compile(
    r"(?:^|[;&|]\s*|\n\s*)"                              # command position
    r"(?:(?:\w+=(?:\"[^\"]*\"|'[^']*'|\S*)\s+)"           # VAR=val prefixes
    r"|(?:env|time|command|exec)\s+)*"                    # env/time wrappers
    r"(?:(?:bash|sh|zsh|python[0-9.]*)\s+)?"              # explicit interpreter
    r"(?:\./)?(?:bin/|scripts/|tools/)?"
    r"(?:check|tests?|run[-_]tests?|runtests)\.(?:sh|bash|py)\b",
    re.IGNORECASE,
)

# Our own block reason. Seeing it in the transcript means we already nudged; see
# the module docstring for why that is the real guard.
#
# It deliberately runs to the end of the first sentence, and is deliberately
# SPLIT across two source lines here. A shorter marker would appear verbatim in
# this file and in the test suite, so `cat hooks/nudge-tests.py` would put it in
# the transcript and silence the nudge for the rest of the session -- a false
# negative, which is worse than the false positive this guard was added to fix.
# tests/test_harness.py asserts no single line of either file contains it.
NUDGE_MARKER = ("Harness check: source files were modified but no tests ran "
                "afterward.")

# a test/check invocation, tolerant of an rtk/sudo/etc. prefix
TEST_RUN = re.compile(
    r"\b("
    r"make\s+(?:-\w+\s+(?:\S+\s+)?)*(check|test|ci)\b|"
    r"pytest\b|python[0-9.]*\s+-m\s+(pytest|unittest)|"
    r"(npm|yarn|pnpm|bun)\s+(run\s+)?test|"
    r"cargo\s+test|go\s+test|tox\b|nox\b|node\s+--test\b|"
    r"gradle\w*\s+\S*test|mvn\s+\S*test|"
    # `bats` needs a left guard: without it, `find -name '*.bats'` reads as a
    # test run. That was the single match in a 527-command session -- it is how
    # a false positive hides a false negative.
    r"(?<![.\w-])bats\b|rspec\b|jest\b|vitest\b|phpunit\b|dotnet\s+test|ctest\b|"
    r"bundle\s+exec\s+rspec"
    r")",
    re.IGNORECASE,
)


def walk_tool_uses(obj):
    """Yield (name, input_dict) for every tool_use anywhere in a transcript line."""
    if isinstance(obj, dict):
        if obj.get("type") == "tool_use":
            yield obj.get("name", ""), obj.get("input", {}) or {}
        for v in obj.values():
            yield from walk_tool_uses(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_tool_uses(v)


def detect_test_cmd(cwd):
    """Best-effort project test command from marker files. None if unknown."""
    def has(name):
        return os.path.exists(os.path.join(cwd, name))

    def read(name, limit=20000):
        try:
            with open(os.path.join(cwd, name), encoding="utf-8", errors="ignore") as fh:
                return fh.read(limit)
        except OSError:
            return ""

    for mk in ("Makefile", "makefile", "GNUmakefile"):
        if has(mk):
            body = read(mk)
            if re.search(r"^check\s*:", body, re.MULTILINE):
                return "make check"
            if re.search(r"^test\s*:", body, re.MULTILINE):
                return "make test"
    # Before the package-manager guesses: a repo whose suite is a checked-in
    # script. Naming it matters as much as finding it -- the nudge has to ask
    # for something PROJECT_TEST_RUN can then see, or the user runs exactly what
    # it asked for and gets nudged again.
    for script in ("bin/check.sh", "bin/test.sh", "scripts/check.sh",
                   "scripts/test.sh", "check.sh", "test.sh", "run-tests.sh"):
        if has(script):
            return "./" + script
    if has("package.json"):
        try:
            pkg = json.loads(read("package.json"))
            if isinstance(pkg.get("scripts"), dict) and "test" in pkg["scripts"]:
                return "npm test"
        except (json.JSONDecodeError, ValueError):
            pass
    if has("tox.ini"):
        return "tox"
    if has("Cargo.toml"):
        return "cargo test"
    if has("go.mod"):
        return "go test ./..."
    if has("build.gradle") or has("build.gradle.kts"):
        return "./gradlew test"
    if has("pom.xml"):
        return "mvn test"
    if has("pyproject.toml") or has("setup.py") or has("pytest.ini") or os.path.isdir(
        os.path.join(cwd, "tests")
    ):
        return "pytest"
    return None


def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return  # allow stop
    # don't loop: if we already blocked once this turn, let it stop
    if data.get("stop_hook_active"):
        return
    cwd = os.path.realpath(data.get("cwd") or os.getcwd())
    transcript = data.get("transcript_path")
    if not transcript or not os.path.exists(transcript):
        return

    last_edit = -1
    last_test = -1
    last_nudge = -1
    edited_something = False
    try:
        with open(transcript, encoding="utf-8", errors="ignore") as fh:
            for idx, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                # Our own past nudge: a plain meta user message plus the
                # hook_blocking_error attachment Claude Code records beside it.
                # Matched on the raw line so it costs nothing on the hot path.
                if NUDGE_MARKER in line:
                    last_nudge = idx
                    # deliberately NOT `continue`: a line can carry both the
                    # marker and a tool_use (an agent grepping for it, say), and
                    # skipping the walk would lose that edit or test run.
                try:
                    rec = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                for name, inp in walk_tool_uses(rec):
                    if name in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
                        path = (inp.get("file_path") or inp.get("notebook_path")
                                or inp.get("path") or "")
                        if not path:
                            continue
                        tgt = os.path.realpath(os.path.expanduser(path))
                        inside = tgt == cwd or tgt.startswith(cwd + os.sep)
                        if inside and tgt.lower().endswith(CODE_EXT):
                            last_edit = idx
                            edited_something = True
                    elif name == "Bash":
                        cmd = inp.get("command", "")
                        if TEST_RUN.search(cmd) or PROJECT_TEST_RUN.search(cmd):
                            last_test = idx
    except OSError:
        return

    # Nudge only if a real source edit happened with no test run after it AND we
    # have not already said so for this same edit-set. A later edit re-arms it;
    # a nudge that Claude answered with "tests are not applicable here" does not
    # come back, which is what the reason text promises.
    if edited_something and last_test < last_edit and last_nudge < last_edit:
        cmd = detect_test_cmd(cwd)
        run = f"`{cmd}`" if cmd else "this project's test suite"
        print(json.dumps({
            "decision": "block",
            "reason": (
                f"Harness check: source files were modified but no tests ran "
                f"afterward. Before finishing, run {run} to confirm the change "
                f"preserved existing functionality. If tests are genuinely not "
                f"applicable here (or the user asked you to skip them), say so "
                f"in one line and stop."
            ),
        }))


if __name__ == "__main__":
    main()
