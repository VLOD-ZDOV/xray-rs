#!/usr/bin/env bash
#
# Install, update or rollback xray-rs core in 3x-ui.
#
set -euo pipefail

XUI_DIR="/usr/local/x-ui"
XUI_BIN_DIR="${XUI_DIR}/bin"
TARGET_BIN="${XUI_BIN_DIR}/xray-linux-amd64"
CONFIG_FILE="${XUI_BIN_DIR}/config.json"
ORIG_BIN="${XUI_BIN_DIR}/xray-linux-amd64.orig"
BAK_BIN="${XUI_BIN_DIR}/xray-linux-amd64.bak"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [PATH_TO_XRAY_SERVER_BINARY]

Installs or updates xray-server into 3x-ui safely with config test and automatic backup.

Options:
    --build         Compile release binary first with cargo build --release -p xray-server
    --rollback      Restore original or previous binary and restart 3x-ui
    -h, --help      Show this help message

Examples:
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

BUILD_FLAG=0
SOURCE_BIN=""

while [ $# -gt 0 ]; do
    case "$1" in
        --build)
            BUILD_FLAG=1
            shift
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
    log_info "Building release binary..."
    if ! command -v cargo &>/dev/null; then
        log_error "Cargo is not found in PATH. Please install Rust or specify prebuilt binary."
        exit 1
    fi
    nice cargo build --release -p xray-server
    SOURCE_BIN="target/release/xray-server"
fi

if [ -z "$SOURCE_BIN" ]; then
    for candidate in "target/release/xray-server" "./xray-server" "./xray-linux-amd64"; do
        if [ -f "$candidate" ]; then
            SOURCE_BIN="$candidate"
            break
        fi
    done
fi

if [ -z "$SOURCE_BIN" ] || [ ! -f "$SOURCE_BIN" ]; then
    log_error "xray-server binary not found."
    log_error "Specify path: $(basename "$0") /path/to/xray-server or use --build."
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

# Preserve original binary if not already backed up
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
