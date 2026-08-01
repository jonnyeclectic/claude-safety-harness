# claude-safety-harness — dev entrypoints.
# The hooks are dependency-free Python stdlib, so the whole suite runs with the
# system interpreter; no venv, no pip. `make check` is the canonical gate CI and
# the nudge-tests Stop hook both point at.

PYTHON ?= python3

.PHONY: help test check lint

help:
	@echo "make test   - run the hook behavioral test suite"
	@echo "make check  - alias for test (canonical CI/pre-finish gate)"
	@echo "make lint   - byte-compile the hooks and bin/ scripts to catch syntax errors"

test:
	$(PYTHON) -m unittest discover -s tests -v

check: test

# PYTHONPYCACHEPREFIX sends .pyc output outside the repo, which is what makes
# this runnable inside a sandboxed `claudex` session: the sandbox denies writes
# to hooks/ (so the agent can't rewrite its own guards), and the default
# in-tree hooks/__pycache__ write fails with EPERM.
#
# The bin/ scripts go through py_compile, NOT compileall. compileall only picks
# up *.py, and `claudex`/`ghapi` are extensionless -- naming them explicitly does
# not help, it skips them and still exits 0, so a syntax error there would lint
# clean. py_compile compiles whatever path it is given.
lint:
	PYTHONPYCACHEPREFIX=$${TMPDIR:-/tmp}/harness-pyc \
		$(PYTHON) -m compileall -q hooks tests
	PYTHONPYCACHEPREFIX=$${TMPDIR:-/tmp}/harness-pyc \
		$(PYTHON) -m py_compile bin/ghapi bin/compose-settings.py
