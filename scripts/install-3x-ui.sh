#!/usr/bin/env bash
#
# Install, update or rollback xray-rs core in 3x-ui.
#
set -euo pipefail

GITHUB_REPO="${GITHUB_REPO:-VLOD-ZDOV/xray-rs}"
XUI_DIR="/usr/local/x-ui"
XUI_BIN_DIR="${XUI_DIR}/bin"
TARGET_BIN="${XUI_BIN_DIR}/xray-linux-amd64"
CONFIG_FILE="${XUI_BIN_DIR}/config.json"
ORIG_BIN="${XUI_BIN_DIR}/xray-linux-amd64.orig"
BAK_BIN="${XUI_BIN_DIR}/xray-linux-amd64.bak"

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

    local arch
    arch="$(uname -m)"
    if [ "$arch" != "x86_64" ] && [ "$arch" != "amd64" ]; then
        log_warn "Current architecture is $arch, but target binary is expected to be x86_64 / amd64."
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

    if systemctl is-active --quiet x-ui; then
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
    local out_bin="${TMP_DIR}/xray-server"

    log_info "Fetching latest release from https://github.com/${GITHUB_REPO}..."

    local asset_names=("xray-server-linux-amd64" "xray-linux-amd64" "xray-server")
    local download_url=""

    # 1. Try resolving asset url via GitHub API
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local json
    if json="$(curl -fsSL -H "Accept: application/vnd.github.v3+json" "$api_url" 2>/dev/null)"; then
        for name in "${asset_names[@]}"; do
            local url
            url="$(echo "$json" | grep -o "\"browser_download_url\": *\"[^\"]*${name}[^\"]*\"" | head -n 1 | cut -d '"' -f 4 || true)"
            if [ -n "$url" ]; then
                download_url="$url"
                break
            fi
        done
    fi

    # 2. Fallback to direct latest release download URL
    if [ -z "$download_url" ]; then
        for name in "${asset_names[@]}"; do
            local test_url="https://github.com/${GITHUB_REPO}/releases/latest/download/${name}"
            if curl -fsSL -I "$test_url" &>/dev/null; then
                download_url="$test_url"
                break
            fi
        done
    fi

    if [ -n "$download_url" ]; then
        log_info "Downloading prebuilt core from $download_url ..."
        if curl -fL --progress-bar -o "$out_bin" "$download_url"; then
            chmod +x "$out_bin"
            SOURCE_BIN="$out_bin"
            return 0
        fi
    fi

    log_warn "Could not download prebuilt release from https://github.com/${GITHUB_REPO}/releases."
    return 1
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

# If no path specified and not building, try downloading latest release from GitHub
if [ -z "$SOURCE_BIN" ]; then
    download_latest_release || true
fi

# Fallback: check local candidates if download was unavailable (e.g. offline dev or unreleased repo)
if [ -z "$SOURCE_BIN" ] || [ ! -f "$SOURCE_BIN" ]; then
    for candidate in "target/release/xray-server" "./xray-server" "./xray-linux-amd64"; do
        if [ -f "$candidate" ]; then
            log_info "Using local binary candidate: $candidate"
            SOURCE_BIN="$candidate"
            break
        fi
    done
fi

if [ -z "$SOURCE_BIN" ] || [ ! -f "$SOURCE_BIN" ]; then
    log_error "No xray-server binary available."
    log_error "No GitHub release found for ${GITHUB_REPO}, and no local binary was specified."
    log_error "Usage: $(basename "$0") /path/to/xray-server or use --build."
    exit 1
fi

require_root
check_environment

log_info "Validating new binary against $CONFIG_FILE ..."
chmod +x "$SOURCE_BIN"
if ! "$SOURCE_BIN" run -test -c "$CONFIG_FILE"; then
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

if systemctl is-active --quiet x-ui; then
    log_info "Successfully installed and started xray-rs in 3x-ui!"
    "$TARGET_BIN" -version || true
else
    log_error "x-ui service failed to start. Automatically rolling back..."
    if [ -f "$BAK_BIN" ]; then
        cp -f "$BAK_BIN" "$TARGET_BIN"
        systemctl start x-ui || true
    fi
    log_error "Restored previous binary. Check 'journalctl -u x-ui -e' for details."
    exit 1
fi
