#!/bin/sh
# agent-lock installer (macOS / Linux).
#
# Prerequisites:
#   - python3 >= 3.8 and tar on PATH
#   - for remote installs: curl or wget, and network access to GitHub
#   - no root privileges needed; everything goes under --prefix (default ~/.local)
#
# Run it either from a cloned repository (./install.sh) or remotely:
#   curl -fsSL https://raw.githubusercontent.com/jakoes-wu/agent-lock/main/install.sh | sh
#
# Re-running is safe: an identical installation is reported as unchanged.
# This script installs the agent-lock command. It does not create the agentnet
# account or load a firewall; that is `agent-lock install`, which you run later.
set -eu

REPO="${AGENT_LOCK_REPO:-jakoes-wu/agent-lock}"
PREFIX="${HOME}/.local"
UNINSTALL=0
MARKER="# managed-by: agent-lock-installer"

usage() {
  cat <<EOF
Usage: install.sh [--prefix DIR] [--uninstall] [-h|--help]

Install the agent-lock command. It does not create an OS account or load a firewall.

Prerequisites:
  python3 >= 3.8 and tar; curl or wget for remote installs.

Options:
  --prefix DIR     install under DIR (default: ~/.local)
                   files: DIR/share/agent-lock and DIR/bin/agent-lock
  --uninstall      remove the agent-lock command and its package files
  -h, --help       show this help

Environment:
  AGENT_LOCK_REF      tag or branch to download (default: latest release)
  AGENT_LOCK_TARBALL  full URL of the source tarball (overrides the above;
                       file:// URLs work, which is how the tests use it)
  AGENT_LOCK_REPO     GitHub repository (default: ${REPO})
  AGENT_LOCK_API      GitHub API base URL (default: https://api.github.com)
  AGENT_LOCK_CODELOAD source archive base URL for branches and old releases
                       (default: https://codeload.github.com)
  AGENT_LOCK_SHA256   expected SHA-256 of AGENT_LOCK_TARBALL
  AGENT_LOCK_REQUIRE_CHECKSUM=1
                       refuse to install anything whose checksum cannot be verified

Releases publish agent-lock-<tag>.tar.gz and SHA256SUMS; the installer
downloads that archive and checks it before installing. Branches and releases
without those assets are installed unverified (a note says so).

The checksum detects a corrupted download. It does not prove the GitHub
account was not compromised.

Examples:
  ./install.sh                                  # from a cloned repository
  ./install.sh --prefix /opt/tools              # custom location
  ./install.sh --uninstall                      # remove the command only
  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | sh
  AGENT_LOCK_REF=main sh install.sh             # install the main branch
EOF
}

log() { printf '[agent-lock-install] %s\n' "$*"; }
die() { printf '[agent-lock-install] error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) [ $# -ge 2 ] || die "--prefix needs a value (see -h)"; PREFIX="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf '[agent-lock-install] error: unknown option: %s (see -h)\n' "$1" >&2; exit 2 ;;
  esac
done

case "$PREFIX" in
  *"'"*) die "--prefix must not contain a single quote" ;;
esac
SHARE_DIR="${PREFIX}/share/agent-lock"
BIN_DIR="${PREFIX}/bin"
WRAPPER="${BIN_DIR}/agent-lock"

if [ "$UNINSTALL" -eq 1 ]; then
  removed=0
  if [ -d "$SHARE_DIR" ]; then rm -rf "$SHARE_DIR"; removed=1; fi
  if [ -d "${SHARE_DIR}.old" ]; then rm -rf "${SHARE_DIR}.old"; removed=1; fi
  for leftover in "${PREFIX}/share"/.agent-lock-stage.*; do
    if [ -d "$leftover" ]; then rm -rf "$leftover"; removed=1; fi
  done
  if [ -f "$WRAPPER" ] && sed -n 2p "$WRAPPER" | grep -qF "$MARKER"; then rm -f "$WRAPPER"; removed=1; fi
  if [ "$removed" -eq 1 ]; then
    log "removed agent-lock from ${PREFIX}"
  else
    log "unchanged: agent-lock is not installed under ${PREFIX}"
  fi
  exit 0
fi

PYTHON="$(command -v python3 || true)"
[ -n "$PYTHON" ] || die "python3 not found; install Python 3.8 or newer"
case "$PYTHON" in
  *"'"*) die "the path of python3 (${PYTHON}) contains a single quote, which the launcher cannot quote" ;;
esac
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' \
  || die "python3 at ${PYTHON} is older than 3.8"
case "$PYTHON" in
  */shims/*)
    # A version-manager shim adds a process on every start. Write the real interpreter.
    REAL_PYTHON="$("$PYTHON" -c 'import sys; print(sys.executable)' 2>/dev/null || true)"
    case "$REAL_PYTHON" in
      *"'"*) REAL_PYTHON="" ;;
    esac
    if [ -n "$REAL_PYTHON" ] && [ -x "$REAL_PYTHON" ]; then
      log "using ${REAL_PYTHON} instead of the shim ${PYTHON}"
      PYTHON="$REAL_PYTHON"
    fi
    ;;
esac

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-lock-install.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Source: the directory next to this script when run from a clone, otherwise a download.
# With `curl ... | sh`, $0 is the shell itself, so only trust $0 when it names this script;
# otherwise a clone in the current directory would be installed by mistake.
SCRIPT_DIR=""
case "$0" in
  *install.sh) SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" || SCRIPT_DIR="" ;;
esac
if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/src/agent_lock/__init__.py" ] && [ -z "${AGENT_LOCK_TARBALL:-}" ]; then
  SRC_PKG="${SCRIPT_DIR}/src/agent_lock"
else
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    die "curl or wget is required to download agent-lock"
  fi
  fetch() {
    if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
    else wget -q "$1" -O "$2"; fi
  }
  TARBALL="${AGENT_LOCK_TARBALL:-}"
  EXPECTED_SHA="${AGENT_LOCK_SHA256:-}"
  API="${AGENT_LOCK_API:-https://api.github.com}"
  CODELOAD="${AGENT_LOCK_CODELOAD:-https://codeload.github.com}"
  if [ -z "$TARBALL" ]; then
    REF="${AGENT_LOCK_REF:-}"
    RELEASE_JSON=""
    if [ -z "$REF" ]; then
      fetch "${API}/repos/${REPO}/releases/latest" "${WORK_DIR}/release.json" 2>/dev/null \
        || die "no release of ${REPO} found; set AGENT_LOCK_REF=main to install the main branch"
      RELEASE_JSON="${WORK_DIR}/release.json"
    elif "$PYTHON" -c 'import re, sys; sys.exit(0 if re.fullmatch(r"v[0-9]+[.][0-9]+[.][0-9]+([-+].*)?", sys.argv[1]) else 1)' "$REF"; then
      # A version tag: its checksum must be checked, so failing to read the release is an error,
      # not a reason to fall back to an unverified download.
      fetch "${API}/repos/${REPO}/releases/tags/${REF}" "${WORK_DIR}/release.json" 2>/dev/null \
        || die "cannot read release ${REF} of ${REPO} (network error, API rate limit or no such tag); set AGENT_LOCK_TARBALL to install anyway"
      RELEASE_JSON="${WORK_DIR}/release.json"
    fi
    ASSET=""
    SUMS=""
    if [ -n "$RELEASE_JSON" ]; then
      # Three lines: the tag, then the URLs of agent-lock-<tag>.tar.gz and SHA256SUMS (empty when not published).
      RELEASE_INFO="$("$PYTHON" -c '
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
tag = data.get("tag_name") or ""
urls = {asset.get("name"): asset.get("browser_download_url") or "" for asset in data.get("assets") or []}
print(tag)
print(urls.get("agent-lock-" + tag + ".tar.gz", ""))
print(urls.get("SHA256SUMS", ""))
' "$RELEASE_JSON")" || die "could not read the release information of ${REPO}"
      REF="$(printf '%s\n' "$RELEASE_INFO" | sed -n 1p)"
      ASSET="$(printf '%s\n' "$RELEASE_INFO" | sed -n 2p)"
      SUMS="$(printf '%s\n' "$RELEASE_INFO" | sed -n 3p)"
      [ -n "$REF" ] || die "could not read the latest release tag; set AGENT_LOCK_REF to a tag or branch"
    fi
    if [ -n "$ASSET" ] && [ -n "$SUMS" ]; then
      TARBALL="$ASSET"
      fetch "$SUMS" "${WORK_DIR}/SHA256SUMS" || die "download failed: ${SUMS}"
      EXPECTED_SHA="$("$PYTHON" -c '
import sys
wanted = sys.argv[2]
for line in open(sys.argv[1], encoding="utf-8"):
    parts = line.split(None, 1)
    # sha256sum writes "<hash>  <name>", or "<hash> *<name>" in binary mode.
    if len(parts) == 2 and parts[1].strip().lstrip("*") == wanted:
        print(parts[0].lower())
        sys.exit(0)
sys.exit(1)
' "${WORK_DIR}/SHA256SUMS" "agent-lock-${REF}.tar.gz")" \
        || die "SHA256SUMS of ${REF} has no entry for agent-lock-${REF}.tar.gz"
    else
      TARBALL="${CODELOAD}/${REPO}/tar.gz/${REF}"
    fi
  fi
  log "downloading ${TARBALL}"
  fetch "$TARBALL" "${WORK_DIR}/src.tar.gz" || die "download failed: ${TARBALL}"
  # Verify before extracting: a mismatch stops here, before anything installed is touched.
  if [ -n "$EXPECTED_SHA" ]; then
    EXPECTED_SHA="$(printf '%s' "$EXPECTED_SHA" | tr 'ABCDEF' 'abcdef')"
    ACTUAL_SHA="$("$PYTHON" -c '
import hashlib, sys
digest = hashlib.sha256()
with open(sys.argv[1], "rb") as handle:
    for block in iter(lambda: handle.read(1 << 20), b""):
        digest.update(block)
print(digest.hexdigest())
' "${WORK_DIR}/src.tar.gz")" || die "could not compute the checksum of ${TARBALL}"
    [ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] \
      || die "checksum mismatch for ${TARBALL}: expected ${EXPECTED_SHA}, got ${ACTUAL_SHA}"
    log "verified sha256 ${ACTUAL_SHA}"
  elif [ "${AGENT_LOCK_REQUIRE_CHECKSUM:-}" = "1" ]; then
    die "${TARBALL} has no published checksum and AGENT_LOCK_REQUIRE_CHECKSUM=1 is set"
  else
    log "note: ${TARBALL} is not verified (no checksum published)"
  fi
  mkdir "${WORK_DIR}/src"
  tar -xzf "${WORK_DIR}/src.tar.gz" -C "${WORK_DIR}/src" || die "cannot extract ${TARBALL}"
  SRC_PKG="$(find "${WORK_DIR}/src" -type d -path '*/src/agent_lock' | head -n 1)"
  [ -n "$SRC_PKG" ] || die "the downloaded archive does not contain src/agent_lock"
fi

# Stage the package, then compare by content hash with what is installed.
STAGE_PARENT="$(dirname "$SHARE_DIR")"
mkdir -p "$STAGE_PARENT" "$BIN_DIR"
tree_hash() {
  "$PYTHON" - "$1" <<'PY'
import hashlib, os, sys
root = sys.argv[1]
digest = hashlib.sha256()
if os.path.isdir(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for name in sorted(filenames):
            if name.endswith(".pyc"):
                continue
            path = os.path.join(dirpath, name)
            digest.update(os.path.relpath(path, root).encode())
            with open(path, "rb") as handle:
                digest.update(hashlib.sha256(handle.read()).digest())
print(digest.hexdigest())
PY
}

# Recover from an interrupted previous install (step 2 done, step 3 not) and drop stale staging dirs.
for leftover in "$STAGE_PARENT"/.agent-lock-stage.*; do
  if [ -d "$leftover" ]; then rm -rf "$leftover"; fi
done
OLD_DIR="${SHARE_DIR}.old"
if [ ! -d "$SHARE_DIR" ] && [ -d "$OLD_DIR" ]; then
  mv "$OLD_DIR" "$SHARE_DIR"
elif [ -d "$OLD_DIR" ]; then
  rm -rf "$OLD_DIR"
fi

NEW_HASH="$(tree_hash "$SRC_PKG")"
OLD_HASH="$(tree_hash "${SHARE_DIR}/agent_lock")"
if [ "$NEW_HASH" = "$OLD_HASH" ]; then
  log "unchanged: ${SHARE_DIR}"
else
  STAGE="$(mktemp -d "${STAGE_PARENT}/.agent-lock-stage.XXXXXX")"
  cp -R "$SRC_PKG" "${STAGE}/agent_lock"
  find "${STAGE}" -name '__pycache__' -type d -prune -exec rm -rf {} +
  # Swap in three renames so an interruption leaves either the old or the new version usable.
  if [ -d "$SHARE_DIR" ]; then mv "$SHARE_DIR" "$OLD_DIR"; fi
  # Test hook: simulate being killed between the two renames; the next run recovers via step 0.
  # It only works together with AGENT_LOCK_TEST_MODE=1, so a stray variable cannot break a real install.
  if [ "${AGENT_LOCK_TEST_MODE:-}" = 1 ] && [ -n "${AGENT_LOCK_TEST_CRASH_SWAP:-}" ]; then rm -rf "$STAGE"; exit 137; fi
  mv "$STAGE" "$SHARE_DIR"
  rm -rf "$OLD_DIR"
  log "installed ${SHARE_DIR}"
fi

WRAPPER_CONTENT="#!/bin/sh
${MARKER}
PYTHONPATH='${SHARE_DIR}'\${PYTHONPATH:+:\$PYTHONPATH} exec '${PYTHON}' -m agent_lock \"\$@\""
if [ -f "$WRAPPER" ] && [ "$(cat "$WRAPPER")" = "$WRAPPER_CONTENT" ]; then
  log "unchanged: ${WRAPPER}"
else
  if [ -e "$WRAPPER" ] && ! sed -n 2p "$WRAPPER" | grep -qF "$MARKER"; then
    die "${WRAPPER} exists and was not created by this installer; remove it or use --prefix"
  fi
  printf '%s\n' "$WRAPPER_CONTENT" > "${WRAPPER}.tmp"
  chmod 755 "${WRAPPER}.tmp"
  mv "${WRAPPER}.tmp" "$WRAPPER"
  log "installed ${WRAPPER}"
fi

path_command() {
  case "$BIN_DIR" in *"'"*) return 1 ;; esac
  case "$(basename "${SHELL:-}")" in
    zsh) printf "echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc" "$BIN_DIR" ;;
    bash)
      if [ "$(uname -s)" = "Darwin" ]; then profile=".bash_profile"; else profile=".bashrc"; fi
      printf "echo 'export PATH=\"%s:\$PATH\"' >> ~/%s" "$BIN_DIR" "$profile" ;;
    fish) printf "fish_add_path '%s'" "$BIN_DIR" ;;
    *) return 1 ;;
  esac
}
case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *)
    if command_text="$(path_command)"; then
      log "note: ${BIN_DIR} is not on PATH; run: ${command_text}, then open a new terminal"
    else
      log "note: ${BIN_DIR} is not on PATH; add it in your shell profile, e.g. export PATH=\"${BIN_DIR}:\$PATH\""
    fi
    ;;
esac
