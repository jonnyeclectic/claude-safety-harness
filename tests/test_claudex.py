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
import json
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
    "CLAUDE_CODE_USE_FOUNDRY",
    "ANTHROPIC_PROFILE",
    "ANTHROPIC_FEDERATION_RULE_ID",
    "ANTHROPIC_ORGANIZATION_ID",
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
        # The account a developer's own session runs under must not leak in.
        self.env.pop("CLAUDE_CONFIG_DIR", None)
        # Nor this machine's managed settings: compose-settings.py reads the
        # OS directory Claude Code reads unless pointed elsewhere. Empty (not
        # even created) unless a test writes a policy into it.
        self.managed_dir = os.path.join(self.tmp, "managed")
        self.env["CLAUDEX_MANAGED_SETTINGS_DIR"] = self.managed_dir

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


# The types Claude Code's settings schema expects for every key these policy
# files may set. Used as a tripwire, not documentation: see
# TestSandboxPolicyContent for why a wrong type here is worse than a wrong value.
POLICY_TYPES = {
    ("sandbox", "enabled"): bool,
    ("sandbox", "failIfUnavailable"): bool,
    ("sandbox", "allowUnsandboxedCommands"): bool,
    ("sandbox", "filesystem", "allowWrite"): list,
    ("sandbox", "filesystem", "denyRead"): list,
    ("sandbox", "filesystem", "allowRead"): list,
    ("sandbox", "filesystem", "denyWrite"): list,
    ("sandbox", "network", "allowLocalBinding"): bool,
    ("sandbox", "network", "allowedDomains"): list,
    ("sandbox", "network", "deniedDomains"): list,
    ("sandbox", "network", "allowManagedDomainsOnly"): bool,
    ("sandbox", "network", "allowUnixSockets"): list,
    ("sandbox", "network", "allowMachLookup"): list,
    ("sandbox", "credentials", "files"): list,
    ("sandbox", "credentials", "envVars"): list,
    ("permissions", "deny"): list,
    ("permissions", "ask"): list,
    ("permissions", "allow"): list,
}


class TestSandboxPolicyContent(ClaudexCase):
    """The policy templates ARE the sandbox, and nothing asserted on their
    contents before -- only that the files exist and get copied.

    Two invariants. First, a key a profile promises has to survive
    `compose-settings.py` into the settings `claude` is actually launched with;
    compose only setdefault()s `sandbox.filesystem.allowWrite`, so everything
    else rides along untouched, but that is a property worth pinning rather than
    assuming.

    Second, and the reason this file gets a type tripwire where the rest of the
    suite gets behavior: a settings file that fails schema validation is skipped
    *whole*, and silently. `failIfUnavailable` lives inside the file that gets
    dropped, so one mistyped value does not fail the launch loudly -- it removes
    the sandbox and hands you a bypassPermissions session with no wall. Verified
    against Claude Code 2.1.273: a `--settings` file identical but for
    `"allowLocalBinding": "yes"` had its every rule ignored, with nothing on
    stdout or stderr to say so.
    """

    def compose(self, template):
        """The composed settings `claudex` would pass to `claude --settings`.

        Run against the $HARNESS_DIR copies, the same trio install.sh ships.
        claudex's own composed file cannot be read after the fact -- its EXIT
        trap deletes the whole workdir before run_claudex() returns.
        """
        out = os.path.join(self.tmp, template + ".composed")
        proc = subprocess.run(
            [sys.executable, os.path.join(self.harness_dir, "compose-settings.py"),
             os.path.join(self.harness_dir, template), "NONE", out],
            capture_output=True, text=True, env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.compose_stderr = proc.stderr
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)

    def write_managed(self, relpath, cfg):
        path = os.path.join(self.managed_dir, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)

    def test_base_allows_binding_a_local_port(self):
        """Without this, anything that talks to a helper process over a local
        socket dies at bind(): dev servers, Playwright, `jest --watch`, and the
        .NET test host. Base already leaves egress open, so it is the profile
        that can afford the loopback surface.

        This buys bind() only. The .NET test host also needs its connect() to
        land, and a dual-stack `TcpClient` reaches loopback as
        `::ffff:127.0.0.1`, which the rule this flag adds does not match -- see
        the `dotnet test` section of the README."""
        cfg = self.compose("sandbox.base.json")
        self.assertIs(cfg["sandbox"]["network"]["allowLocalBinding"], True)

    def test_strict_pins_local_binding_off(self):
        """The one that must not drift. On macOS the same flag also emits
        `(allow network-outbound (remote ip "localhost:*"))`, which reaches
        loopback WITHOUT traversing the egress proxy -- and the proxy is the
        only thing enforcing strict's `deniedDomains: ["*"]`. One `ssh -D`, one
        mitmproxy, one sibling claudex session's proxy, and strict's single
        stated guarantee is gone with no violation recorded.

        Leaving the key out is not enough: Claude Code 2.1.274 honors
        `sandbox.network.allowLocalBinding` from a repo's own
        `.claude/settings.json` (it is not on the list of sandbox keys project
        settings may not set). The `--settings` file outranks project and
        local settings, so only an explicit `false` here keeps an untrusted
        repo from turning it back on."""
        network = self.compose("sandbox.strict.json")["sandbox"]["network"]
        self.assertIs(network.get("allowLocalBinding"), False)
        self.assertEqual(network["deniedDomains"], ["*"])

    def test_base_turns_local_binding_off_under_the_managed_allowlist(self):
        """The template's own `false` (below) is not enough on every machine.
        Claude Code keeps only the highest managed source for merged settings
        -- server-managed settings, then an MDM profile, then this file -- but
        reads `allowManagedDomainsOnly` from all of them. With org-pushed
        settings present, the allow-list still applies while the file's
        `false` is dropped, and base's `true` reopens the localhost route
        around it. claudex writes the `--settings` file, so it can look for
        the allow-list itself and not ask for binding in the first place."""
        with open(os.path.join(REPO_ROOT, "settings", "managed-network-allowlist.json"),
                  encoding="utf-8") as fh:
            self.write_managed("managed-settings.json", json.load(fh))
        cfg = self.compose("sandbox.base.json")
        self.assertIs(cfg["sandbox"]["network"]["allowLocalBinding"], False)
        self.assertIn("allow-list", self.compose_stderr)

    def test_managed_allowlist_in_a_drop_in_is_seen_too(self):
        """install.sh refuses to overwrite an existing managed-settings.json,
        so an allow-list can just as well arrive as a managed-settings.d
        drop-in merged over a hooks-only base file."""
        self.write_managed("managed-settings.json",
                           {"hooks": {"PreToolUse": []}})
        self.write_managed("managed-settings.d/50-network.json",
                           {"sandbox": {"network": {"allowManagedDomainsOnly": True,
                                                    "allowedDomains": ["pypi.org"]}}})
        cfg = self.compose("sandbox.base.json")
        self.assertIs(cfg["sandbox"]["network"]["allowLocalBinding"], False)

    def test_managed_allowlist_saved_with_a_byte_order_mark_is_seen(self):
        """Claude Code 2.1.274 reads a managed file that starts with a UTF-8
        BOM, or with the UTF-16LE one, and applies it. Python's json refuses
        both, and skipping the file would leave base binding on under a live
        allow-list. Files saved on Windows or by MDM tooling carry them."""
        with open(os.path.join(REPO_ROOT, "settings", "managed-network-allowlist.json"),
                  encoding="utf-8") as fh:
            text = fh.read()
        for label, data in (("utf-8", b"\xef\xbb\xbf" + text.encode("utf-8")),
                            ("utf-16le", b"\xff\xfe" + text.encode("utf-16-le"))):
            with self.subTest(bom=label):
                os.makedirs(self.managed_dir, exist_ok=True)
                with open(os.path.join(self.managed_dir, "managed-settings.json"), "wb") as fh:
                    fh.write(data)
                cfg = self.compose("sandbox.base.json")
                self.assertIs(cfg["sandbox"]["network"]["allowLocalBinding"], False)

    def test_a_later_mistyped_drop_in_does_not_hide_the_allowlist(self):
        """Claude Code drops a managed file's whole `sandbox` key when any value
        in it has the wrong type, so a later drop-in with
        `"allowManagedDomainsOnly": "false"` leaves the earlier `true` in
        force. Counting the allow-list as on whenever any file sets it true
        errs toward binding off, the safe side."""
        self.write_managed("managed-settings.json",
                           {"sandbox": {"network": {"allowManagedDomainsOnly": True,
                                                    "allowedDomains": ["pypi.org"]}}})
        self.write_managed("managed-settings.d/50-typo.json",
                           {"sandbox": {"network": {"allowManagedDomainsOnly": "false"}}})
        cfg = self.compose("sandbox.base.json")
        self.assertIs(cfg["sandbox"]["network"]["allowLocalBinding"], False)

    def test_managed_settings_without_the_allowlist_leave_binding_on(self):
        """A managed file that only installs hooks -- common on company
        machines -- must not cost base its dev servers."""
        self.write_managed("managed-settings.json",
                           {"hooks": {"PreToolUse": []}})
        cfg = self.compose("sandbox.base.json")
        self.assertIs(cfg["sandbox"]["network"]["allowLocalBinding"], True)
        self.assertEqual(self.compose_stderr, "")

    def test_managed_allowlist_turns_local_binding_back_off(self):
        """The managed allow-list filters base claudex too, so base's
        `allowLocalBinding: true` would hand every session the same direct
        localhost connect strict refuses: route through any local proxy and
        the allow-list never sees the request.

        Managed settings outrank the `--settings` file claudex launches with
        (Claude Code 2.1.274 merges user < project < local < flag < policy),
        so an explicit `false` here wins over base's `true`, and covers plain
        `claude` too. That holds only while this file is the managed source in
        effect; the compose-side check below covers the rest."""
        with open(os.path.join(REPO_ROOT, "settings", "managed-network-allowlist.json"),
                  encoding="utf-8") as fh:
            network = json.load(fh)["sandbox"]["network"]
        self.assertIs(network["allowManagedDomainsOnly"], True)
        self.assertIs(network.get("allowLocalBinding"), False)

    def test_trusted_roots_do_not_disturb_the_rest_of_the_policy(self):
        """compose() injects into sandbox.filesystem.allowWrite; every sibling
        key must round-trip untouched."""
        roots_file = os.path.join(self.tmp, "roots.txt")
        with open(roots_file, "w", encoding="utf-8") as fh:
            fh.write(self.tmp + "\n")
        out = os.path.join(self.tmp, "with-roots.json")
        proc = subprocess.run(
            [sys.executable, os.path.join(self.harness_dir, "compose-settings.py"),
             os.path.join(self.harness_dir, "sandbox.base.json"), roots_file, out],
            capture_output=True, text=True, env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(out, encoding="utf-8") as fh:
            cfg = json.load(fh)
        self.assertEqual(cfg["sandbox"]["filesystem"]["allowWrite"],
                         [os.path.realpath(self.tmp)])
        self.assertIs(cfg["sandbox"]["network"]["allowLocalBinding"], True)
        self.assertIs(cfg["sandbox"]["enabled"], True)
        self.assertIs(cfg["sandbox"]["allowUnsandboxedCommands"], False)

    def test_every_policy_value_has_the_type_the_schema_expects(self):
        """A wrong type voids a `--settings` file whole, and drops the entire
        `sandbox` key of a managed file -- the sandbox either way."""
        for template in ("sandbox.base.json", "sandbox.strict.json",
                         "managed-network-allowlist.json"):
            with self.subTest(template=template):
                with open(os.path.join(REPO_ROOT, "settings", template),
                          encoding="utf-8") as fh:
                    cfg = json.load(fh)
                for path, value in self.leaves(cfg):
                    expected = POLICY_TYPES.get(path)
                    self.assertIsNotNone(
                        expected,
                        "%s sets %s, which this test does not know the type of. "
                        "Add it to POLICY_TYPES -- a key that reaches Claude "
                        "Code untyped is a key that can void the file."
                        % (template, ".".join(path)))
                    self.assertIsInstance(
                        value, expected,
                        "%s: %s should be %s, got %r"
                        % (template, ".".join(path), expected.__name__, value))

    @staticmethod
    def leaves(cfg):
        """(path, value) for each setting, descending only into plain objects.

        Keys starting with `_` are comments (the repo's existing convention in
        settings/managed-network-allowlist.json) and are skipped; Claude Code
        drops unknown keys rather than rejecting the file.
        """
        out = []

        def walk(node, path):
            for key, value in node.items():
                if key.startswith("_"):
                    continue
                if isinstance(value, dict):
                    walk(value, path + (key,))
                else:
                    out.append((path + (key,), value))

        walk(cfg, ())
        return out


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


class TestAccountSelection(ClaudexCase):
    """--account <name> picks the Claude config dir (~/.<name>) -- and with it
    the cached login, plugins and history -- the same way a
    `CLAUDE_CONFIG_DIR=$HOME/.claude-personal claude` alias does.

    Claude Code keys the stored login by the literal CLAUDE_CONFIG_DIR string,
    and uses the unsuffixed default only when the variable is unset. Verified
    against 2.1.272: `CLAUDE_CONFIG_DIR=$HOME/.claude claude auth status`
    reports loggedIn=false while the same account is logged in with the
    variable unset. So the default account must unset it, never set it.
    """

    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "home")
        for name in (".claude", ".claude-personal"):
            os.makedirs(os.path.join(self.home, name))
        self.env["HOME"] = self.home

    def test_account_sets_the_config_dir(self):
        proc = self.run_claudex(["--account", "claude-personal"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.stub_env().get("CLAUDE_CONFIG_DIR"),
                         os.path.join(self.home, ".claude-personal"))
        self.assertIn(os.path.join(self.home, ".claude-personal"), proc.stderr)

    def test_equals_form(self):
        proc = self.run_claudex(["--account=claude-personal"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.stub_env().get("CLAUDE_CONFIG_DIR"),
                         os.path.join(self.home, ".claude-personal"))

    def test_config_dir_is_the_literal_home_path(self):
        """The login is keyed by the exact string, so no realpath or trailing
        slash: it must match what `CLAUDE_CONFIG_DIR=$HOME/.claude-x claude`
        stored at login, even when $HOME is reached through a symlink."""
        linked_home = os.path.join(self.tmp, "home-link")
        os.symlink(self.home, linked_home)
        self.env["HOME"] = linked_home
        proc = self.run_claudex(["--account", "claude-personal"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.stub_env().get("CLAUDE_CONFIG_DIR"),
                         linked_home + "/.claude-personal")

    def test_default_account_unsets_the_config_dir(self):
        proc = self.run_claudex(["--account", "claude"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("CLAUDE_CONFIG_DIR", self.stub_env())
        self.assertIn("(default)", proc.stderr)

    def test_default_account_equals_form(self):
        proc = self.run_claudex(["--account=claude"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("CLAUDE_CONFIG_DIR", self.stub_env())

    def test_account_is_consumed_wherever_it_appears(self):
        proc = self.run_claudex(
            ["-p", "hi", "--account", "claude-personal", "--strict", "--verbose"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.stub_tail_argv(), ["-p", "hi", "--verbose"])
        self.assertIn("STRICT", proc.stderr)

    def test_no_flag_leaves_the_config_dir_unset(self):
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("CLAUDE_CONFIG_DIR", self.stub_env())
        self.assertIn(os.path.join(self.home, ".claude"), proc.stderr)

    def test_no_flag_keeps_an_inherited_config_dir(self):
        inherited = os.path.join(self.home, ".claude-personal")
        self.env["CLAUDE_CONFIG_DIR"] = inherited
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.stub_env().get("CLAUDE_CONFIG_DIR"), inherited)
        self.assertIn(inherited, proc.stderr)

    def test_default_account_overrides_an_inherited_config_dir(self):
        """Switching back from a `claude-personal` shell to the default login."""
        self.env["CLAUDE_CONFIG_DIR"] = os.path.join(self.home, ".claude-personal")
        proc = self.run_claudex(["--account", "claude"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("CLAUDE_CONFIG_DIR", self.stub_env())

    def test_named_account_overrides_an_inherited_config_dir(self):
        os.makedirs(os.path.join(self.home, ".claude-work"))
        self.env["CLAUDE_CONFIG_DIR"] = os.path.join(self.home, ".claude-personal")
        proc = self.run_claudex(["--account", "claude-work"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.stub_env().get("CLAUDE_CONFIG_DIR"),
                         os.path.join(self.home, ".claude-work"))

    def assertRefused(self, args, *needles):
        proc = self.run_claudex(args)
        self.assertNotEqual(proc.returncode, 0, proc.stderr)
        self.assertIsNone(self.stub_argv(), "claude must not launch")
        self.assertNotIn("unbound variable", proc.stderr)
        for needle in needles:
            self.assertIn(needle, proc.stderr)

    def test_missing_value_is_refused(self):
        self.assertRefused(["--account"], "--account")

    def test_empty_value_is_refused(self):
        self.assertRefused(["--account="], "--account")

    def test_non_claude_name_is_refused(self):
        os.makedirs(os.path.join(self.home, ".ssh"))
        self.assertRefused(["--account", "ssh"], "ssh")

    def test_path_in_name_is_refused(self):
        self.assertRefused(["--account", "claude-x/../../etc"], "claude-x/../../etc")

    def test_account_without_a_config_dir_is_refused(self):
        self.assertRefused(["--account", "claude-work"],
                           os.path.join(self.home, ".claude-work"))

    def test_wrong_case_name_is_refused(self):
        """macOS's default APFS is case-insensitive, so `-d ~/.claude-Personal`
        is true while the login is keyed by the exact string: a case typo would
        start a logged-out session on top of the real account's files. On a
        case-sensitive filesystem (Linux CI) this passes either way; macOS is
        where it guards the exact-name match."""
        self.assertRefused(["--account", "claude-Personal"],
                           os.path.join(self.home, ".claude-Personal"))

    def test_env_credentials_outranking_the_account_are_flagged(self):
        """Picking an account does nothing for auth if an env key wins anyway."""
        self.env["ANTHROPIC_API_KEY"] = "sk-ant-api03-test"
        proc = self.run_claudex(["--account", "claude-personal"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("warning", proc.stderr)
        self.assertIn("ANTHROPIC_API_KEY", proc.stderr)

    def test_env_credentials_with_the_default_account_are_flagged(self):
        """The default account has no CLAUDE_CONFIG_DIR to name; must not
        trip `set -u` while building the warning."""
        self.env["ANTHROPIC_API_KEY"] = "sk-ant-api03-test"
        proc = self.run_claudex(["--account", "claude"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("unbound variable", proc.stderr)
        self.assertIn("warning", proc.stderr)
        self.assertIn("ANTHROPIC_API_KEY", proc.stderr)

    def test_other_credentials_that_outrank_a_login_are_flagged(self):
        """Per the authentication-precedence docs, these win over /login too."""
        for extra in ({"CLAUDE_CODE_USE_FOUNDRY": "1"},
                      {"ANTHROPIC_PROFILE": "work"},
                      {"ANTHROPIC_FEDERATION_RULE_ID": "rule",
                       "ANTHROPIC_ORGANIZATION_ID": "org"}):
            with self.subTest(extra=extra):
                self.env.update(extra)
                try:
                    proc = self.run_claudex(["--account", "claude-personal"])
                finally:
                    for k in extra:
                        self.env.pop(k, None)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("warning", proc.stderr)
                self.assertIn(sorted(extra)[0], proc.stderr)

    def test_half_a_federation_pair_is_not_flagged(self):
        """Federation credentials apply only when both variables are set."""
        self.env["ANTHROPIC_ORGANIZATION_ID"] = "org"
        proc = self.run_claudex(["--account", "claude-personal"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("warning", proc.stderr)

    def test_non_credential_auth_context_is_not_flagged(self):
        self.env["ANTHROPIC_MODEL"] = "claude-opus-5"
        proc = self.run_claudex(["--account", "claude-personal"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("warning", proc.stderr)

    def test_env_credentials_without_the_flag_are_not_flagged(self):
        self.env["ANTHROPIC_API_KEY"] = "sk-ant-api03-test"
        proc = self.run_claudex([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("warning", proc.stderr)


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
