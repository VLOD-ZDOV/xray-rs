#!/usr/bin/env bash
#
# Install, update or rollback xray-rs core in 3x-ui.
#
set -euo pipefail

GITHUB_REPO="${GITHUB_REPO:-VLOD-ZDOV/xray-rs}"
XUI_DIR="/usr/local/x-ui"
XUI_BIN_DIR="${XUI_DIR}/bin"
CONFIG_FILE="${XUI_BIN_DIR}/config.json"

# The panel's core name and the release file for this CPU. 3x-ui runs every
# 32-bit ARM host as xray-linux-arm32.
case "$(uname -m)" in
    x86_64 | x64 | amd64) CORE_NAME="xray-linux-amd64"; ASSET="xray-linux-amd64" ;;
    i*86 | x86) CORE_NAME="xray-linux-386"; ASSET="xray-linux-386" ;;
    aarch64 | arm64 | armv8*) CORE_NAME="xray-linux-arm64"; ASSET="xray-linux-arm64" ;;
    armv7* | arm) CORE_NAME="xray-linux-arm32"; ASSET="xray-linux-arm32" ;;
    armv6*) CORE_NAME="xray-linux-arm32"; ASSET="xray-linux-arm32-v6" ;;
    armv5*) CORE_NAME="xray-linux-arm32"; ASSET="xray-linux-arm32-v5" ;;
    s390x) CORE_NAME="xray-linux-s390x"; ASSET="xray-linux-s390x" ;;
    *) CORE_NAME=""; ASSET="" ;;
esac
TARGET_BIN="${XUI_BIN_DIR}/${CORE_NAME}"
ORIG_BIN="${TARGET_BIN}.orig"
BAK_BIN="${TARGET_BIN}.bak"

TMP_DIR=""
cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [PATH_TO_XRAY_SERVER_BINARY]

Installs or updates xray-server into 3x-ui safely with config test and automatic backup.
By default, downloads the latest release binary from GitHub (${GITHUB_REPO}).

Options:
    --build         Compile release binary from source (cargo build --release -p xray-server)
    --repo <REPO>   GitHub repository to download from (default: ${GITHUB_REPO})
    --rollback      Restore original or previous binary and restart 3x-ui
    -h, --help      Show this help message

Examples:
    # One-liner to install / update from latest GitHub release:
    curl -fsSL https://raw.githubusercontent.com/${GITHUB_REPO}/main/scripts/install-3x-ui.sh | sudo bash

    # Local usage:
    sudo ./scripts/install-3x-ui.sh
    sudo ./scripts/install-3x-ui.sh --build
    sudo ./scripts/install-3x-ui.sh /path/to/xray-server
    sudo ./scripts/install-3x-ui.sh --rollback
EOF
    exit 0
}

log_info() {
    echo -e "\033[1;32m[INFO]\033[0m $*"
}

log_warn() {
    echo -e "\033[1;33m[WARN]\033[0m $*"
}

log_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $*" >&2
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root (or with sudo)."
        exit 1
    fi
}

check_environment() {
    if [ "$(uname -s)" != "Linux" ]; then
        log_error "This script only supports Linux."
        exit 1
    fi

    if [ -z "$CORE_NAME" ]; then
        log_error "Unsupported CPU architecture: $(uname -m)."
        exit 1
    fi

    if [ ! -d "$XUI_BIN_DIR" ]; then
        log_error "3x-ui installation directory not found at $XUI_BIN_DIR"
        exit 1
    fi

    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "3x-ui config file not found at $CONFIG_FILE"
        exit 1
    fi
}

# x-ui stays active even when the core it runs keeps failing, so check the core too.
core_running() {
    sleep 5
    systemctl is-active --quiet x-ui && pidof "$CORE_NAME" >/dev/null
}

do_rollback() {
    require_root
    check_environment

    local restore_from=""
    if [ -f "$ORIG_BIN" ]; then
        restore_from="$ORIG_BIN"
    elif [ -f "$BAK_BIN" ]; then
        restore_from="$BAK_BIN"
    else
        log_error "Neither $ORIG_BIN nor $BAK_BIN found to roll back from."
        exit 1
    fi

    log_info "Rolling back from $restore_from ..."
    systemctl stop x-ui || true
    cp -f "$restore_from" "$TARGET_BIN"
    chmod 755 "$TARGET_BIN"
    systemctl start x-ui

    if core_running; then
        log_info "Rollback successful. x-ui is active."
        "$TARGET_BIN" -version || true
    else
        log_error "Failed to start x-ui after rollback. Check 'journalctl -u x-ui -e'."
        exit 1
    fi
    exit 0
}

download_latest_release() {
    TMP_DIR="$(mktemp -d -t xray-rs-XXXXXX)"
    local base="https://github.com/${GITHUB_REPO}/releases/latest/download"
    log_info "Downloading the latest release from ${base} ..."
    if ! curl -fL --progress-bar -o "${TMP_DIR}/${ASSET}" "${base}/${ASSET}" ||
        ! curl -fsSL -o "${TMP_DIR}/${ASSET}.sha256" "${base}/${ASSET}.sha256"; then
        log_error "No release found in https://github.com/${GITHUB_REPO}/releases."
        log_error "Pass a binary path or use --build."
        exit 1
    fi
    if ! (cd "$TMP_DIR" && sha256sum --check --quiet "${ASSET}.sha256"); then
        log_error "Checksum mismatch, the download is corrupted."
        exit 1
    fi
    SOURCE_BIN="${TMP_DIR}/${ASSET}"
}

BUILD_FLAG=0
SOURCE_BIN=""

while [ $# -gt 0 ]; do
    case "$1" in
        --build)
            BUILD_FLAG=1
            shift
            ;;
        --repo)
            GITHUB_REPO="$2"
            shift 2
            ;;
        --rollback)
            do_rollback
            ;;
        -h|--help)
            usage
            ;;
        -*)
            log_error "Unknown option: $1"
            usage
            ;;
        *)
            SOURCE_BIN="$1"
            shift
            ;;
    esac
done

if [ "$BUILD_FLAG" -eq 1 ]; then
    log_info "Building release binary from source..."
    if ! command -v cargo &>/dev/null; then
        log_error "Cargo is not found in PATH. Please install Rust or omit --build to download prebuilt binary."
        exit 1
    fi
    nice cargo build --release -p xray-server
    SOURCE_BIN="target/release/xray-server"
fi

if [ -z "$SOURCE_BIN" ]; then
    check_environment
    download_latest_release
fi

if [ ! -f "$SOURCE_BIN" ]; then
    log_error "Binary not found: $SOURCE_BIN"
    exit 1
fi

require_root
check_environment

log_info "Validating new binary against $CONFIG_FILE ..."
chmod +x "$SOURCE_BIN"
# The candidate runs from a temporary path, so point it at the panel's geo files.
if ! XRAY_LOCATION_ASSET="$XUI_BIN_DIR" "$SOURCE_BIN" run -test -c "$CONFIG_FILE"; then
    log_error "Config test failed with $SOURCE_BIN."
    log_error "Aborting installation without touching the running service."
    exit 1
fi
log_info "Config test passed."

# Preserve original official binary if not already backed up
if [ -f "$TARGET_BIN" ] && [ ! -f "$ORIG_BIN" ]; then
    log_info "Backing up original core to $ORIG_BIN ..."
    cp -a "$TARGET_BIN" "$ORIG_BIN"
fi

# Always maintain a rollback copy of currently installed binary
if [ -f "$TARGET_BIN" ]; then
    cp -a "$TARGET_BIN" "$BAK_BIN"
fi

log_info "Installing new binary to $TARGET_BIN ..."
cp -f "$SOURCE_BIN" "${TARGET_BIN}.new"
chmod 755 "${TARGET_BIN}.new"

log_info "Restarting x-ui service..."
systemctl stop x-ui
mv -f "${TARGET_BIN}.new" "$TARGET_BIN"
systemctl start x-ui

if core_running; then
    log_info "Successfully installed and started xray-rs in 3x-ui!"
    "$TARGET_BIN" -version || true
else
    log_error "The core is not running under x-ui. Rolling back..."
    if [ -f "$BAK_BIN" ]; then
        systemctl stop x-ui || true
        cp -f "$BAK_BIN" "$TARGET_BIN"
        systemctl start x-ui || true
    fi
    log_error "Restored previous binary. Check 'journalctl -u x-ui -e' for details."
    exit 1
fi
