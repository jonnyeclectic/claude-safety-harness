# claude-safety-harness — dev entrypoints.
# The hooks are dependency-free Python stdlib, so the whole suite runs with the
# system interpreter; no venv, no pip. `make check` is the canonical gate CI and
# the nudge-tests Stop hook both point at.

PYTHON ?= python3

.PHONY: help test check lint

help:
	@echo "make test   - run the hook behavioral test suite"
	@echo "make check  - alias for test (canonical CI/pre-finish gate)"
	@echo "make lint   - byte-compile the hooks to catch syntax errors"

test:
	$(PYTHON) -m unittest discover -s tests -v

check: test

lint:
	$(PYTHON) -m compileall -q hooks tests
