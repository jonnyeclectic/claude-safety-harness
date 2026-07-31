#!/usr/bin/env python3
"""Behavioral tests for bin/claudex, the sandboxed launcher script.

These exercise the real script as a subprocess (real bash, real
compose-settings.py, real sandbox.*.json templates — the same trio
install.sh copies into $HARNESS_DIR) with a stub `claude` on PATH standing
in for the actual CLI, so we can assert on what it would have been invoked
with.

Regression coverage: `claudex` passes two bash arrays --
``"${add_dirs[@]}"`` and ``"${pass_args[@]}"`` -- to the final `claude`
invocation, and either can legitimately be empty (no trusted roots
configured, or claudex invoked with no extra args). Under
``set -euo pipefail``, bash 3.2 -- which is what ``/usr/bin/env bash``
resolves to on a stock macOS install, since Apple has shipped 3.2 for
license reasons since 10.15 -- raises "unbound variable" when expanding an
*empty* array this way, even though the array was declared with `foo=()`.
The fix is the `"${arr[@]+"${arr[@]}"}"` guard idiom, which is a no-op on
every bash version.

CI runs on ubuntu-latest, whose bash is 5.x and does not have this bug, so
a behavioral run there can't distinguish the fixed script from the broken
one -- it would pass either way. TestArrayExpansionGuardPresent below is a
static source check that fails in CI if the guard is ever removed, which is
the only way this specific regression is caught outside of macOS.
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLAUDEX = os.path.join(REPO_ROOT, "bin", "claudex")

STUB_CLAUDE = """#!/usr/bin/env bash
printf '%s\\n' "$@" > "$CLAUDE_STUB_OUT"
env > "$CLAUDE_STUB_OUT.env"
"""

# Auth-context vars claudex forwards. Scrubbed from every test environment in
# setUp so a real key in the developer's shell can't decide the outcome.
AUTH_ENV_VARS = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL",
    "ANTHROPIC_BASE_URL",
    "CMUX_PRESERVE_CLAUDE_AUTH_SELECTION_ENV",
    "CLAUDEX_NO_AUTH_PASSTHROUGH",
)


class ClaudexCase(unittest.TestCase):
    """Run bin/claudex as a real subprocess with a stubbed `claude` on PATH."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="claudex-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        # $HARNESS_DIR: the same three files install.sh copies there.
        self.harness_dir = os.path.join(self.tmp, "harness")
        os.makedirs(self.harness_dir)
        for f in ("sandbox.base.json", "sandbox.strict.json"):
            shutil.copy(os.path.join(REPO_ROOT, "settings", f), self.harness_dir)
        compose = shutil.copy(
            os.path.join(REPO_ROOT, "bin", "compose-settings.py"), self.harness_dir)
        os.chmod(compose, 0o755)

        # A stub `claude` on PATH that records its argv instead of launching.
        stub_bin = os.path.join(self.tmp, "stub-bin")
        os.makedirs(stub_bin)
        stub_path = os.path.join(stub_bin, "claude")
        with open(stub_path, "w", encoding="utf-8") as fh:
            fh.write(STUB_CLAUDE)
        os.chmod(stub_path, os.stat(stub_path).st_mode | stat.S_IEXEC
                  | stat.S_IXGRP | stat.S_IXOTH)

        self.stub_out = os.path.join(self.tmp, "claude-argv.txt")

        self.env = dict(os.environ)
        self.env["PATH"] = stub_bin + os.pathsep + self.env.get("PATH", "")
        self.env["CLAUDEX_HARNESS_DIR"] = self.harness_dir
        # No trusted-roots file by default -> compose-settings.py treats it
        # as "NONE" and add_dirs stays empty. Individual tests override this.
        self.env["CLAUDEX_TRUSTED_ROOTS"] = os.path.join(self.tmp, "no-such-roots.txt")
        self.env["CLAUDE_STUB_OUT"] = self.stub_out
        self.env["TMPDIR"] = tempfile.gettempdir()
        for var in AUTH_ENV_VARS:
            self.env.pop(var, None)

    def run_claudex(self, args=()):
        return subprocess.run(
            ["bash", CLAUDEX, *args], capture_output=True, text=True, env=self.env)

    def stub_argv(self):
        """Args the stub `claude` was actually invoked with, or None if never run."""
        if not os.path.exists(self.stub_out):
            return None
        with open(self.stub_out, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        return lines

    def stub_tail_argv(self):
        """stub_argv() with the fixed `--dangerously-skip-permissions --settings
        <tmp path>` prefix stripped off, leaving just the add_dirs/pass_args tail
        under test. The settings path is a fresh mktemp dir each run, so callers
        that care about the full invocation shape should use stub_argv() instead.
        """
        argv = self.stub_argv()
        self.assertIsNotNone(argv, "stub claude was never invoked")
        self.assertEqual(argv[:2], ["--dangerously-skip-permissions", "--settings"],
                          argv)
        return argv[3:]

    def stub_env(self):
        """Environment the stub `claude` was actually launched with."""
        path = self.stub_out + ".env"
        self.assertTrue(os.path.exists(path), "stub claude was never invoked")
        env = {}
        with open(path, encoding="utf-8") as fh:
            for line in fh.read().splitlines():
                key, sep, value = line.partition("=")
                if sep:
                    env[key] = value
        return env


class TestNoCrashOnEmptyArrays(ClaudexCase):
    """The core regression: empty add_dirs/pass_args must not crash under set -u."""

    def test_no_args_no_trusted_roots(self):
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("unbound variable", proc.stderr)
        self.assertEqual(self.stub_tail_argv(), [])

    def test_strict_no_extra_args(self):
        proc = self.run_claudex(["--strict"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("unbound variable", proc.stderr)
        self.assertEqual(self.stub_tail_argv(), [])


class TestArgPassthrough(ClaudexCase):
    """--strict is consumed; everything else reaches `claude` unchanged."""

    def test_strict_is_stripped(self):
        proc = self.run_claudex(["--strict", "-p", "hello world"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.stub_tail_argv(), ["-p", "hello world"])
        self.assertIn("STRICT", proc.stderr)

    def test_non_strict_args_passed_through_untouched(self):
        proc = self.run_claudex(["-p", "do the thing", "--verbose"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.stub_tail_argv(), ["-p", "do the thing", "--verbose"])
        self.assertNotIn("STRICT", proc.stderr)


class TestTrustedRootsAddDir(ClaudexCase):
    """A non-empty add_dirs array must also survive the expansion unharmed."""

    def setUp(self):
        super().setUp()
        self.trusted_dir = os.path.join(self.tmp, "sibling-project")
        os.makedirs(self.trusted_dir)
        roots_file = os.path.join(self.tmp, "roots.txt")
        with open(roots_file, "w", encoding="utf-8") as fh:
            fh.write(self.trusted_dir + "\n")
        self.env["CLAUDEX_TRUSTED_ROOTS"] = roots_file

    def test_trusted_root_becomes_add_dir(self):
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            self.stub_tail_argv(), ["--add-dir", os.path.realpath(self.trusted_dir)])

    def test_trusted_root_combined_with_passthrough_args(self):
        proc = self.run_claudex(["foo", "bar"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            self.stub_tail_argv(),
            ["--add-dir", os.path.realpath(self.trusted_dir), "foo", "bar"])


class TestAuthContextPassthrough(ClaudexCase):
    """The caller's Anthropic auth context must survive the trip to `claude`.

    A terminal's `claude` shim can scrub auth on the way through -- cmux
    unsets ANTHROPIC_API_KEY and friends so a new pane can't inherit a stale
    key -- which silently downgraded a claudex session to whatever
    credentials were cached on disk. claudex now opts into that wrapper's
    preserve hatch whenever the caller actually set auth context, and always
    reports which source won.
    """

    def test_api_key_opts_into_the_wrapper_preserve_hatch(self):
        self.env["ANTHROPIC_API_KEY"] = "sk-ant-api03-test"
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        env = self.stub_env()
        self.assertEqual(env.get("CMUX_PRESERVE_CLAUDE_AUTH_SELECTION_ENV"), "1")
        self.assertEqual(env.get("ANTHROPIC_API_KEY"), "sk-ant-api03-test")
        self.assertIn("ANTHROPIC_API_KEY", proc.stderr)

    def test_bedrock_selector_also_counts_as_auth_context(self):
        self.env["CLAUDE_CODE_USE_BEDROCK"] = "1"
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            self.stub_env().get("CMUX_PRESERVE_CLAUDE_AUTH_SELECTION_ENV"), "1")

    def test_no_auth_env_leaves_the_wrapper_alone(self):
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(
            "CMUX_PRESERVE_CLAUDE_AUTH_SELECTION_ENV", self.stub_env())
        self.assertIn("cached login", proc.stderr)

    def test_escape_hatch_defers_to_the_wrapper(self):
        self.env["ANTHROPIC_API_KEY"] = "sk-ant-api03-test"
        self.env["CLAUDEX_NO_AUTH_PASSTHROUGH"] = "1"
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(
            "CMUX_PRESERVE_CLAUDE_AUTH_SELECTION_ENV", self.stub_env())

    def test_empty_auth_var_is_not_auth_context(self):
        self.env["ANTHROPIC_API_KEY"] = ""
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(
            "CMUX_PRESERVE_CLAUDE_AUTH_SELECTION_ENV", self.stub_env())
        self.assertIn("cached login", proc.stderr)

    def test_api_key_in_the_oauth_token_var_is_flagged(self):
        """The mistake that 401s mid-session instead of failing at launch."""
        self.env["CLAUDE_CODE_OAUTH_TOKEN"] = "sk-ant-api03-wrong-var"
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("CLAUDE_CODE_OAUTH_TOKEN", proc.stderr)
        self.assertIn("sk-ant-oat01-", proc.stderr)

    def test_real_oauth_token_is_not_flagged(self):
        self.env["CLAUDE_CODE_OAUTH_TOKEN"] = "sk-ant-oat01-fine"
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("warning", proc.stderr)

    def test_auth_passthrough_does_not_disturb_argv(self):
        self.env["ANTHROPIC_API_KEY"] = "sk-ant-api03-test"
        proc = self.run_claudex(["--strict", "-p", "hi"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.stub_tail_argv(), ["-p", "hi"])


class TestArrayExpansionGuardPresent(unittest.TestCase):
    """Static guard: CI's ubuntu bash is 5.x and can't reproduce the macOS
    bash-3.2 empty-array bug behaviorally (see module docstring), so this is
    the check that actually fails if the guard idiom is reverted.
    """

    def test_add_dirs_and_pass_args_use_the_safe_guard(self):
        with open(CLAUDEX, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn('"${add_dirs[@]+"${add_dirs[@]}"}"', src,
                      "add_dirs expansion must use the bash-3.2-safe guard idiom")
        self.assertIn('"${pass_args[@]+"${pass_args[@]}"}"', src,
                      "pass_args expansion must use the bash-3.2-safe guard idiom")


if __name__ == "__main__":
    unittest.main()
