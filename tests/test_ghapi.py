#!/usr/bin/env python3
"""Behavioral tests for bin/ghapi, the sandbox-safe GitHub API client.

`ghapi` exists because Go's TLS stack cannot verify certificates inside the
Seatbelt sandbox -- it reaches trustd over XPC, which is denied, so every `gh`
request fails with `x509: OSStatus -26276` and `gh auth status` misreports it
as an invalid token. See the bin/ghapi docstring for the full diagnosis.

These run the real script as a subprocess with a stub `curl` on PATH (the same
approach test_claudex.py takes with a stub `claude`), so the whole suite is
offline and tokenless -- it must pass in CI, which has neither network access
to api.github.com nor a GITHUB_TOKEN.

The stub records the argv it was called with so we can assert on the request
ghapi *would* have made, and honours the -o/-D/-w contract ghapi relies on:
body to the -o file, headers to the -D file, HTTP status on stdout.
"""
import json
import os
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GHAPI = os.path.join(REPO, "bin", "ghapi")

# Stub curl: writes canned body/headers where ghapi asked, echoes the status on
# stdout (ghapi's -w '%{http_code}'), and appends its own argv to $ARGV_LOG.
STUB_CURL = r'''#!/usr/bin/env python3
import json, os, sys
argv = sys.argv[1:]
with open(os.environ["ARGV_LOG"], "a") as f:
    f.write(json.dumps(argv) + "\n")

def opt(flag):
    return argv[argv.index(flag) + 1] if flag in argv else None

body = os.environ.get("STUB_BODY", "{}")
status = os.environ.get("STUB_STATUS", "200")
link = ""

# `auth status` calls /user then /rate_limit; serve each its own shape.
if argv and "rate_limit" in argv[-1]:
    body = ('{"unexpected": true}' if os.environ.get("STUB_RATE_BROKEN")
            else '{"resources": {"core": {"remaining": 4999, "limit": 5000}}}')

# Two-page walk: page 2 is served only when the URL says page=2.
if os.environ.get("STUB_PAGINATE"):
    url = argv[-1]
    if "page=2" in url:
        body = '[{"n": 3}]'
    else:
        body = '[{"n": 1}, {"n": 2}]'
        link = '<https://api.github.com/x?page=2>; rel="next"'

if opt("--data-binary") == "@-":
    # Drain stdin so ghapi never blocks, and record the payload so tests can
    # assert on the request body without ghapi needing a test-only flag.
    sent = sys.stdin.read()
    if os.environ.get("STDIN_LOG"):
        open(os.environ["STDIN_LOG"], "w").write(sent)

out = opt("-o")
if out:
    open(out, "w").write(body)
head = opt("-D")
if head:
    # Mimic the sandbox proxy: a CONNECT block precedes the real response, so
    # tests catch any code that greps the whole dump instead of the last block.
    open(head, "w").write(
        "HTTP/1.1 200 Connection Established\r\nx-oauth-scopes: PROXY-DECOY\r\n\r\n"
        "HTTP/2 %s\r\n%s%s\r\n" % (
            status,
            ("link: " + link + "\r\n") if link else "",
            os.environ.get("STUB_HEADERS", ""),
        ))
sys.stdout.write(status)
'''


class GhapiTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bindir = os.path.join(self.tmp.name, "bin")
        os.makedirs(self.bindir)
        stub = os.path.join(self.bindir, "curl")
        with open(stub, "w") as f:
            f.write(STUB_CURL)
        os.chmod(stub, 0o755)
        self.argv_log = os.path.join(self.tmp.name, "argv.log")
        self.stdin_log = os.path.join(self.tmp.name, "stdin.log")

    def run_ghapi(self, args, env=None, cwd=None, token="test-token-123"):
        e = dict(os.environ)
        e["PATH"] = self.bindir + os.pathsep + e["PATH"]
        e["ARGV_LOG"] = self.argv_log
        e["STDIN_LOG"] = self.stdin_log
        e.pop("GH_TOKEN", None)
        if token is None:
            e.pop("GITHUB_TOKEN", None)
        else:
            e["GITHUB_TOKEN"] = token
        e.update(env or {})
        return subprocess.run([GHAPI] + args, capture_output=True, text=True,
                              env=e, cwd=cwd or REPO)

    def curl_argv(self, n=0):
        with open(self.argv_log) as f:
            return json.loads(f.read().splitlines()[n])

    def curl_call_count(self):
        with open(self.argv_log) as f:
            return len(f.read().splitlines())

    def sent_body(self):
        """The JSON payload ghapi piped to curl's stdin."""
        with open(self.stdin_log) as f:
            return json.load(f)


class TestRequestShape(GhapiTestCase):
    def test_bare_endpoint_is_a_get_against_api_github(self):
        r = self.run_ghapi(["user"])
        self.assertEqual(r.returncode, 0, r.stderr)
        argv = self.curl_argv()
        self.assertEqual(argv[-1], "https://api.github.com/user")
        self.assertEqual(argv[argv.index("-X") + 1], "GET")

    def test_leading_slash_does_not_double_up(self):
        self.run_ghapi(["/user"])
        self.assertEqual(self.curl_argv()[-1], "https://api.github.com/user")

    def test_full_url_is_passed_through_untouched(self):
        self.run_ghapi(["https://api.github.com/rate_limit"])
        self.assertEqual(self.curl_argv()[-1],
                         "https://api.github.com/rate_limit")

    def test_fields_imply_post(self):
        self.run_ghapi(["repos/o/r/issues", "-f", "title=hi"])
        argv = self.curl_argv()
        self.assertEqual(argv[argv.index("-X") + 1], "POST")

    def test_explicit_method_wins_over_inferred(self):
        self.run_ghapi(["-X", "PATCH", "repos/o/r/issues/1", "-f", "state=closed"])
        argv = self.curl_argv()
        self.assertEqual(argv[argv.index("-X") + 1], "PATCH")

    def test_api_version_and_accept_headers_are_sent(self):
        self.run_ghapi(["user"])
        argv = self.curl_argv()
        self.assertIn("Accept: application/vnd.github+json", argv)
        self.assertIn("X-GitHub-Api-Version: 2022-11-28", argv)

    def test_custom_header_flag_is_forwarded(self):
        self.run_ghapi(["user", "-H", "X-Custom: yes"])
        self.assertIn("X-Custom: yes", self.curl_argv())


class TestTokenHandling(GhapiTestCase):
    def test_token_is_never_passed_in_argv(self):
        """It goes in a --config file so it can't be read out of `ps`."""
        self.run_ghapi(["user"], token="super-secret-value")
        self.assertNotIn("super-secret-value", json.dumps(self.curl_argv()))
        self.assertIn("--config", self.curl_argv())

    def test_missing_token_is_a_clear_error_not_a_traceback(self):
        r = self.run_ghapi(["user"], token=None)
        self.assertEqual(r.returncode, 1)
        self.assertIn("GITHUB_TOKEN", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_gh_token_is_accepted_as_a_fallback(self):
        r = self.run_ghapi(["user"], token=None, env={"GH_TOKEN": "from-gh"})
        self.assertEqual(r.returncode, 0, r.stderr)


class TestFieldTyping(GhapiTestCase):
    """`-f` keeps strings; `-F` infers JSON scalars -- matching gh."""

    def test_raw_field_keeps_numeric_string_as_string(self):
        self.run_ghapi(["x", "-f", "n=42"])
        self.assertEqual(self.sent_body()["n"], "42")

    def test_typed_field_coerces_scalars(self):
        self.run_ghapi(["x", "-F", "n=42", "-F", "ok=true", "-F", "nil=null"])
        body = self.sent_body()
        self.assertEqual(body["n"], 42)
        self.assertIs(body["ok"], True)
        self.assertIsNone(body["nil"])

    def test_bracket_suffix_accumulates_a_list(self):
        self.run_ghapi(["x", "-f", "labels[]=bug", "-f", "labels[]=p1"])
        self.assertEqual(self.sent_body()["labels"], ["bug", "p1"])


class TestRepoPlaceholders(GhapiTestCase):
    def test_owner_repo_resolve_from_origin_remote(self):
        repo = os.path.join(self.tmp.name, "proj")
        os.makedirs(repo)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "remote", "add", "origin",
                        "https://github.com/acme/widgets.git"],
                       cwd=repo, check=True)
        self.run_ghapi(["repos/{owner}/{repo}/pulls"], cwd=repo)
        self.assertEqual(self.curl_argv()[-1],
                         "https://api.github.com/repos/acme/widgets/pulls")

    def test_ssh_remote_form_also_parses(self):
        repo = os.path.join(self.tmp.name, "proj2")
        os.makedirs(repo)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "remote", "add", "origin",
                        "git@github.com:acme/widgets.git"],
                       cwd=repo, check=True)
        self.run_ghapi(["repos/{owner}/{repo}"], cwd=repo)
        self.assertEqual(self.curl_argv()[-1],
                         "https://api.github.com/repos/acme/widgets")

    def test_no_remote_is_a_clear_error(self):
        repo = os.path.join(self.tmp.name, "proj3")
        os.makedirs(repo)
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        r = self.run_ghapi(["repos/{owner}/{repo}"], cwd=repo)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("Traceback", r.stderr)


class TestPagination(GhapiTestCase):
    def test_paginate_follows_link_rel_next_and_concatenates(self):
        r = self.run_ghapi(["items", "--paginate"], env={"STUB_PAGINATE": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), [{"n": 1}, {"n": 2}, {"n": 3}])
        self.assertEqual(self.curl_call_count(), 2)

    def test_without_paginate_only_the_first_page_is_fetched(self):
        r = self.run_ghapi(["items"], env={"STUB_PAGINATE": "1"})
        self.assertEqual(json.loads(r.stdout), [{"n": 1}, {"n": 2}])
        self.assertEqual(self.curl_call_count(), 1)

    def test_search_style_items_envelope_merges_on_items(self):
        r = self.run_ghapi(["search/code", "--paginate"],
                           env={"STUB_BODY": '{"total_count": 1, "items": [{"a": 1}]}'})
        self.assertEqual(json.loads(r.stdout)["items"], [{"a": 1}])

    def test_unmergeable_object_returns_first_page_rather_than_erroring(self):
        r = self.run_ghapi(["user", "--paginate"],
                           env={"STUB_BODY": '{"login": "octocat"}'})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["login"], "octocat")


class TestErrorHandling(GhapiTestCase):
    def test_http_error_exits_nonzero_with_the_body_on_stderr(self):
        r = self.run_ghapi(["repos/o/nope"],
                           env={"STUB_STATUS": "404",
                                "STUB_BODY": '{"message": "Not Found"}'})
        self.assertEqual(r.returncode, 1)
        self.assertIn("404", r.stderr)
        self.assertIn("Not Found", r.stderr)

    def test_unknown_flag_is_rejected_rather_than_sent_to_curl(self):
        r = self.run_ghapi(["user", "--wat"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("unknown flag", r.stderr)
        self.assertFalse(os.path.exists(self.argv_log))

    def test_graphql_errors_exit_nonzero_despite_http_200(self):
        """GraphQL reports failures in a 200 body; a 0 exit would hide them."""
        r = self.run_ghapi(
            ["graphql", "-f", "query={viewer{login}}"],
            env={"STUB_BODY": '{"errors": [{"message": "Bad credentials"}]}'})
        self.assertEqual(r.returncode, 1)
        self.assertIn("Bad credentials", r.stderr)


class TestIncludeHeaders(GhapiTestCase):
    def test_include_prints_response_headers_before_the_body(self):
        r = self.run_ghapi(["user", "-i"], env={"STUB_BODY": '{"login": "octocat"}'})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("HTTP/2 200", r.stdout)
        self.assertLess(r.stdout.index("HTTP/2 200"), r.stdout.index("octocat"))

    def test_include_shows_githubs_headers_not_the_proxy_connect_block(self):
        """curl -D dumps the CONNECT tunnel's headers first; those must not win."""
        r = self.run_ghapi(["user", "-i"],
                           env={"STUB_HEADERS": "x-oauth-scopes: repo\r\n"})
        self.assertIn("x-oauth-scopes: repo", r.stdout)
        self.assertNotIn("PROXY-DECOY", r.stdout)
        self.assertNotIn("Connection Established", r.stdout)

    def test_body_is_unchanged_without_include(self):
        r = self.run_ghapi(["user"], env={"STUB_BODY": '{"login": "octocat"}'})
        self.assertNotIn("HTTP/2", r.stdout)


class TestAuthStatus(GhapiTestCase):
    """`ghapi auth status` exists because the real `gh auth status` reports the
    sandbox TLS failure as an invalid token -- the one command you'd use to
    check credentials is the one that lies about them."""

    def status(self, **env):
        e = {"STUB_BODY": '{"login": "octocat"}',
             "STUB_HEADERS": "x-oauth-scopes: repo, workflow\r\n"}
        e.update(env)
        return self.run_ghapi(["auth", "status"], env=e)

    def test_reports_login_scopes_and_token_source(self):
        r = self.status()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("octocat", r.stdout)
        self.assertIn("repo, workflow", r.stdout)
        self.assertIn("GITHUB_TOKEN", r.stdout)

    def test_scopes_come_from_github_not_the_proxy_block(self):
        self.assertNotIn("PROXY-DECOY", self.status().stdout)

    def test_explains_that_gh_itself_is_the_broken_part(self):
        self.assertIn("trustd", self.status().stdout)

    def test_reports_rate_limit(self):
        self.assertIn("4999/5000", self.status().stdout)

    def test_missing_token_fails_cleanly(self):
        r = self.run_ghapi(["auth", "status"], token=None)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("Traceback", r.stderr)

    def test_unexpected_rate_limit_shape_degrades_instead_of_crashing(self):
        """A nicety must never turn a working auth check into a traceback."""
        r = self.status(STUB_RATE_BROKEN="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("octocat", r.stdout)
        self.assertNotIn("rate limit", r.stdout)

    def test_unimplemented_auth_subcommands_are_explicit(self):
        r = self.run_ghapi(["auth", "login"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("auth status", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_auth_is_not_treated_as_an_api_endpoint(self):
        """Regression: `auth status` must not GET /auth."""
        self.run_ghapi(["auth", "login"])
        self.assertFalse(os.path.exists(self.argv_log))


class TestGraphQL(GhapiTestCase):
    def test_graphql_posts_to_the_graphql_endpoint(self):
        self.run_ghapi(["graphql", "-f", "query={viewer{login}}"],
                       env={"STUB_BODY": '{"data": {}}'})
        argv = self.curl_argv()
        self.assertEqual(argv[-1], "https://api.github.com/graphql")
        self.assertEqual(argv[argv.index("-X") + 1], "POST")

    def test_graphql_without_a_query_is_a_clear_error(self):
        r = self.run_ghapi(["graphql"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("query", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
