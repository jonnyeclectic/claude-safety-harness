#!/usr/bin/env bash
# install.sh — set up the claude-safety-harness for global use.
#
#   ./install.sh                       install the plugin (hooks), the `claudex`
#                                      launcher, and the sandbox policy files.
#   sudo ./install.sh --managed-allowlist
#                                      (optional) install a GLOBAL hard network
#                                      allow-list via OS managed settings.
#
# Idempotent and non-destructive: it never rewrites your ~/.claude/settings.json
# (the sandbox is applied per-launch by `claudex` via --settings).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="$HOME/.claude"
HARNESS_DIR="$CLAUDE_DIR/harness"
BIN_DIR="$HOME/.local/bin"
MARKETPLACE="claude-safety-harness"
PLUGIN="bypass-safety-harness"

info() { printf '  %s\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Optional: install the global managed allow-list (needs root; see template).
# ---------------------------------------------------------------------------
install_managed_allowlist() {
  [ "$(id -u)" -eq 0 ] || die "--managed-allowlist must be run with sudo."
  local src="$REPO_DIR/settings/managed-network-allowlist.json" dest
  case "$(uname -s)" in
    Darwin) dest="/Library/Application Support/ClaudeCode/managed-settings.json" ;;
    Linux)  dest="/etc/claude-code/managed-settings.json" ;;
    *)      die "Unsupported OS for managed settings: $(uname -s)" ;;
  esac
  if [ -e "$dest" ]; then
    die "$dest already exists. Merge the network block from
       $src by hand so existing managed policy isn't clobbered."
  fi
  mkdir -p "$(dirname "$dest")"
  cp "$src" "$dest"
  ok "Installed global managed allow-list → $dest"
  warn "This restricts EVERY claude session (plain claude + base claudex too),"
  warn "not just 'claudex --strict'. Remove the file to undo."
}

if [ "${1:-}" = "--managed-allowlist" ]; then
  install_managed_allowlist
  exit 0
fi

# ---------------------------------------------------------------------------
# 1. Preflight
# ---------------------------------------------------------------------------
command -v claude  >/dev/null 2>&1 || die "'claude' is not on PATH."
command -v python3 >/dev/null 2>&1 || die "'python3' is not on PATH."
case "$(uname -s)" in
  Darwin) ok "macOS detected — Seatbelt sandbox is built in." ;;
  Linux)  warn "Linux: the sandbox needs bubblewrap + socat → sudo apt-get install bubblewrap socat" ;;
  *)      warn "Unrecognized OS $(uname -s); the OS sandbox may be unavailable." ;;
esac

# ---------------------------------------------------------------------------
# 2. Plugin (hooks) at user scope, from this local clone
# ---------------------------------------------------------------------------
info "Registering marketplace + installing plugin (user scope)…"
claude plugin marketplace add "$REPO_DIR" --scope user >/dev/null 2>&1 \
  || info "marketplace '$MARKETPLACE' already registered (or refreshed)."
if claude plugin install "$PLUGIN@$MARKETPLACE" --scope user >/dev/null 2>&1; then
  ok "Plugin '$PLUGIN' installed."
else
  warn "Plugin install returned nonzero — it may already be installed. Check: claude plugin list"
fi

# ---------------------------------------------------------------------------
# 3. Sandbox policy files + compose helper → ~/.claude/harness/
# ---------------------------------------------------------------------------
mkdir -p "$HARNESS_DIR"
cp "$REPO_DIR/settings/sandbox.base.json"   "$HARNESS_DIR/"
cp "$REPO_DIR/settings/sandbox.strict.json" "$HARNESS_DIR/"
cp "$REPO_DIR/bin/compose-settings.py"      "$HARNESS_DIR/"
chmod +x "$HARNESS_DIR/compose-settings.py"
ok "Policy files → $HARNESS_DIR/ (edit these to tune the sandbox; no reinstall needed)."

# ---------------------------------------------------------------------------
# 4. Launcher → ~/.local/bin/claudex
# ---------------------------------------------------------------------------
mkdir -p "$BIN_DIR"
cp "$REPO_DIR/bin/claudex" "$BIN_DIR/claudex"
chmod +x "$BIN_DIR/claudex"
ok "Launcher → $BIN_DIR/claudex"
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) warn "$BIN_DIR is not on your PATH — add it, e.g.: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc" ;;
esac

# ---------------------------------------------------------------------------
# 5. Seed the trusted-roots file (only if absent)
# ---------------------------------------------------------------------------
if [ ! -f "$CLAUDE_DIR/harness-trusted-roots.txt" ]; then
  cp "$REPO_DIR/harness-trusted-roots.example.txt" "$CLAUDE_DIR/harness-trusted-roots.txt"
  ok "Seeded $CLAUDE_DIR/harness-trusted-roots.txt (list sibling repos to allow writes to)."
else
  info "Kept existing $CLAUDE_DIR/harness-trusted-roots.txt"
fi

cat <<EOF

Done. Start a NEW claude session so the plugin hooks load (verify with /hooks).

  claudex            sandboxed bypass here — writes limited to project + temp
  claudex --strict   + no subprocess network, secret files/env hidden

Optional global hard allow-list (affects ALL claude sessions):
  sudo $REPO_DIR/install.sh --managed-allowlist

Uninstall:  $REPO_DIR/uninstall.sh
EOF
