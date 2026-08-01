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

if [ "${1:-}" = "--managed-allowlist" ]; then
  [ "$(id -u)" -eq 0 ] || die "--managed-allowlist must be run with sudo."
  case "$(uname -s)" in
    Darwin) dest="/Library/Application Support/ClaudeCode/managed-settings.json" ;;
    Linux)  dest="/etc/claude-code/managed-settings.json" ;;
    *)      die "Unsupported OS: $(uname -s)" ;;
  esac
  if [ -e "$dest" ]; then rm -f "$dest"; ok "Removed $dest"; else warn "No managed allow-list at $dest"; fi
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
