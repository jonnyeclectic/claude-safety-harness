#!/usr/bin/env python3
"""Behavioral tests for the two scripts that touch OS managed settings.

`install.sh --managed-allowlist` and `uninstall.sh --managed-allowlist` write
and remove a file that every `claude` session on the machine obeys, and on a
company Mac that file is very often *not* ours: MDM ships hooks, allowed MCP
servers or login policy in the same `managed-settings.json`. install.sh has
always refused to overwrite one. uninstall.sh used to `rm -f` it whole, which
took the company's policy with it -- and the README tells people to merge our
block into an existing file by hand, which is exactly the case that hurts.

Both scripts take the directory from `CLAUDEX_MANAGED_SETTINGS_DIR` when it is
set, which is what lets these tests run without root or a real /Library write.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL = os.path.join(REPO_ROOT, "install.sh")
UNINSTALL = os.path.join(REPO_ROOT, "uninstall.sh")
TEMPLATE = os.path.join(REPO_ROOT, "settings", "managed-network-allowlist.json")


class ManagedAllowlistCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="harness-managed-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.managed_dir = os.path.join(self.tmp, "ClaudeCode")
        os.makedirs(self.managed_dir)
        self.dest = os.path.join(self.managed_dir, "managed-settings.json")
        self.env = dict(os.environ)
        self.env["CLAUDEX_MANAGED_SETTINGS_DIR"] = self.managed_dir

    def run_script(self, script):
        return subprocess.run(["bash", script, "--managed-allowlist"],
                              capture_output=True, text=True, env=self.env)

    def write_dest(self, cfg):
        with open(self.dest, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)

    def template(self):
        with open(TEMPLATE, encoding="utf-8") as fh:
            return json.load(fh)


class TestManagedAllowlistInstall(ManagedAllowlistCase):
    def test_installs_the_template_into_an_empty_directory(self):
        proc = self.run_script(INSTALL)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(self.dest, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), self.template())

    def test_refuses_to_clobber_an_existing_managed_file(self):
        self.write_dest({"hooks": {"PreToolUse": []}})
        proc = self.run_script(INSTALL)
        self.assertNotEqual(proc.returncode, 0)
        with open(self.dest, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), {"hooks": {"PreToolUse": []}})


class TestManagedAllowlistUninstall(ManagedAllowlistCase):
    def test_removes_a_file_this_repo_installed(self):
        self.write_dest(self.template())
        proc = self.run_script(UNINSTALL)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(self.dest))

    def test_refuses_to_delete_a_file_carrying_other_policy(self):
        """The case the README's "merge it by hand" advice creates: our sandbox
        block living next to a company hook. Deleting the file would silently
        remove the hook from every session on the machine."""
        merged = self.template()
        merged["hooks"] = {"PreToolUse": [{"matcher": "Bash"}]}
        self.write_dest(merged)
        proc = self.run_script(UNINSTALL)
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(os.path.exists(self.dest))
        self.assertIn("hooks", proc.stderr)
        with open(self.dest, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), merged)

    def test_refuses_to_delete_a_managed_file_that_is_not_an_allowlist(self):
        """No `sandbox` block of ours in it at all: someone else's file that
        happens to sit where ours would."""
        self.write_dest({"sandbox": {"enabled": True}})
        proc = self.run_script(UNINSTALL)
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(os.path.exists(self.dest))

    def test_refuses_when_the_policy_lives_inside_the_sandbox_block(self):
        """The shape install.sh's own advice produces: a company file whose
        only top-level key is `sandbox`, carrying their command exemptions,
        denied domains and credential denies next to our allow-list. Judging by
        top-level keys alone would delete all of it."""
        merged = self.template()
        merged["sandbox"]["excludedCommands"] = ["/usr/local/corp/agent:*"]
        merged["sandbox"]["network"]["deniedDomains"] = ["*.pastebin.com"]
        merged["sandbox"]["credentials"] = {"files": [{"path": "/etc/corp/token",
                                                       "mode": "deny"}]}
        self.write_dest(merged)
        proc = self.run_script(UNINSTALL)
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(os.path.exists(self.dest))
        self.assertIn("excludedCommands", proc.stderr)

    def test_edited_allowed_domains_are_still_ours_to_remove(self):
        """The README tells people to edit allowedDomains before installing, so
        a different list is expected -- it is new *keys* that mean someone
        else's policy is in here."""
        edited = self.template()
        edited["sandbox"]["network"]["allowedDomains"] = ["api.anthropic.com"]
        self.write_dest(edited)
        proc = self.run_script(UNINSTALL)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(self.dest))

    def test_reads_a_byte_order_marked_copy_of_our_own_template(self):
        """Claude Code applies a BOM'd managed file, and compose-settings.py
        reads one; this checker refusing it would tell the user their own
        allow-list is somebody else's policy."""
        with open(TEMPLATE, encoding="utf-8") as fh:
            text = fh.read()
        with open(self.dest, "wb") as fh:
            fh.write(b"\xef\xbb\xbf" + text.encode("utf-8"))
        proc = self.run_script(UNINSTALL)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(self.dest))

    def test_refuses_someone_elses_allowlist_with_the_same_shape(self):
        """A corporate managed allow-list has the same natural key set as ours:
        allowManagedDomainsOnly plus allowedDomains. Key paths alone can't tell
        them apart, so the file this repo installs carries a marker."""
        theirs = {"sandbox": {"enabled": True, "allowUnsandboxedCommands": False,
                              "network": {"allowLocalBinding": False,
                                          "allowManagedDomainsOnly": True,
                                          "allowedDomains": ["*.acme.internal"]}}}
        self.write_dest(theirs)
        proc = self.run_script(UNINSTALL)
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(os.path.exists(self.dest))
        with open(self.dest, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), theirs)

    def test_the_installed_file_carries_the_marker_it_is_judged_by(self):
        proc = self.run_script(INSTALL)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(self.dest, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh).get("_installedBy"),
                             "claude-safety-harness")

    def test_says_so_when_there_is_nothing_to_remove(self):
        proc = self.run_script(UNINSTALL)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
