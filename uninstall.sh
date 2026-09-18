#!/usr/bin/env bash
# uninstall.sh — remove the launcher, policy files, and plugin.
# Leaves your ~/.claude/harness-trusted-roots.txt and harness-audit.log in place
# (delete them by hand if you want them gone).
#
#   ./uninstall.sh                       remove launcher + policy files + plugin
#   sudo ./uninstall.sh --managed-allowlist
#                                        remove the global managed allow-list
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="$HOME/.claude"
HARNESS_DIR="$CLAUDE_DIR/harness"
BIN_DIR="$HOME/.local/bin"
MARKETPLACE="claude-safety-harness"
PLUGIN="bypass-safety-harness"

ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

# The directory Claude Code reads file-based managed settings from.
# CLAUDEX_MANAGED_SETTINGS_DIR replaces it, which is how the tests exercise
# this path without root; a replaced directory needs no sudo, since it is
# somewhere the caller can already write.
managed_settings_dir() {
  if [ -n "${CLAUDEX_MANAGED_SETTINGS_DIR:-}" ]; then
    printf '%s\n' "$CLAUDEX_MANAGED_SETTINGS_DIR"
    return 0
  fi
  [ "$(id -u)" -eq 0 ] || die "--managed-allowlist must be run with sudo."
  case "$(uname -s)" in
    Darwin) printf '%s\n' "/Library/Application Support/ClaudeCode" ;;
    Linux)  printf '%s\n' "/etc/claude-code" ;;
    *)      die "Unsupported OS: $(uname -s)" ;;
  esac
}

# Only delete a file that is ours and ours alone. install.sh refuses to
# overwrite an existing managed-settings.json and tells you to merge our
# sandbox block into it by hand, and a company Mac keeps hooks, MCP policy or
# login rules in that same file -- rm -f would take those with it, for every
# session on the machine.
file_is_only_our_allowlist() {
  python3 "$REPO_DIR/bin/is-harness-allowlist.py" "$1"
}

if [ "${1:-}" = "--managed-allowlist" ]; then
  dest="$(managed_settings_dir)/managed-settings.json"
  if [ ! -e "$dest" ] && [ ! -L "$dest" ]; then
    warn "No managed allow-list at $dest"
    exit 0
  fi
  if [ -L "$dest" ] && [ ! -e "$dest" ]; then
    die "$dest is a symlink with no target. Remove it by hand."
  fi
  command -v python3 >/dev/null 2>&1 \
    || die "python3 is needed to check whether $dest holds anything but this repo's allow-list."
  status=0
  reason="$(file_is_only_our_allowlist "$dest" 2>&1)" || status=$?
  if [ "$status" -eq 2 ]; then
    die "Refusing to delete $dest -- $reason
       Fix or remove it by hand; while it is unreadable, no claude session on
       this machine will start."
  elif [ "$status" -ne 0 ]; then
    die "Refusing to delete $dest -- $reason
       It holds policy this repo did not install, and deleting the file would
       drop that from every claude session. Remove this repo's keys by hand."
  fi
  if [ -L "$dest" ]; then
    target="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$dest")"
    rm -f "$dest"
    ok "Removed the symlink at $dest; its target $target is untouched."
    exit 0
  fi
  rm -f "$dest"
  ok "Removed $dest"
  exit 0
fi

# Launcher + sandbox-safe GitHub client
if [ -e "$BIN_DIR/claudex" ]; then rm -f "$BIN_DIR/claudex"; ok "Removed $BIN_DIR/claudex"; fi
if [ -e "$BIN_DIR/ghapi" ]; then rm -f "$BIN_DIR/ghapi"; ok "Removed $BIN_DIR/ghapi"; fi

# Policy files
for f in sandbox.base.json sandbox.strict.json compose-settings.py; do
  [ -e "$HARNESS_DIR/$f" ] && rm -f "$HARNESS_DIR/$f"
done
rmdir "$HARNESS_DIR" 2>/dev/null && ok "Removed $HARNESS_DIR/" || warn "Left $HARNESS_DIR/ (not empty or absent)."

# Plugin
if command -v claude >/dev/null 2>&1; then
  claude plugin uninstall "$PLUGIN@$MARKETPLACE" >/dev/null 2>&1 \
    && ok "Uninstalled plugin '$PLUGIN'." \
    || warn "Could not uninstall plugin automatically — try: claude plugin uninstall $PLUGIN@$MARKETPLACE"
fi

cat <<EOF

Done. Left in place (delete by hand if you want):
  $CLAUDE_DIR/harness-trusted-roots.txt
  $CLAUDE_DIR/harness-audit.log
EOF
