#!/bin/sh
# yip Turnkey POSIX Installer
# https://github.com/femboyisp/yip
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/femboyisp/yip/main/install.sh | sh
#
# Environment Overrides:
#   VERSION           - Specific version to install (e.g. '0.1.0' or 'v0.1.0', default: latest)
#   REPO              - GitHub repository (default: 'femboyisp/yip')
#   BINDIR            - Target directory for binaries (default: '/usr/local/bin')
#   CONFDIR           - Target directory for configs (default: '/etc/yip')
#   INIT_SYSTEM       - Init system ('auto', 'systemd', 'openrc', 'runit', 'none', default: 'auto')
#   SYSD_DIR          - systemd unit directory (default: '/etc/systemd/system')
#   OPENRC_DIR        - OpenRC service directory (default: '/etc/init.d')
#   RUNIT_DIR         - runit service directory (default: '/etc/sv')
#   LOCAL_TARBALL     - Path to local tarball (for offline/sandbox testing)
#   LOCAL_SHA256SUMS  - Path to local SHA256SUMS file (for offline/sandbox testing)
#   TARGET            - Explicit target triple override (e.g. 'x86_64-unknown-linux-musl')

set -e

# --- 1. Privilege Escalation Detection ---
# If running as non-root and installing to default system paths, use sudo/doas.
# If custom directory overrides are provided (e.g. sandbox testing), skip sudo/doas.
if [ -z "${SUDO+x}" ]; then
    SUDO=""
    if [ "$(id -u)" -ne 0 ]; then
        if [ -n "${BINDIR+x}" ] || [ -n "${CONFDIR+x}" ] || [ -n "${SYSD_DIR+x}" ] || [ -n "${OPENRC_DIR+x}" ] || [ -n "${RUNIT_DIR+x}" ]; then
            # Custom directory overrides detected: running in unprivileged sandbox mode
            SUDO=""
        else
            if command -v sudo >/dev/null 2>&1; then
                SUDO="sudo"
            elif command -v doas >/dev/null 2>&1; then
                SUDO="doas"
            else
                echo "Error: Root privileges required to install to standard paths (/usr/local/bin, /etc/yip)." >&2
                echo "Neither 'sudo' nor 'doas' was found. Re-run as root or specify destination directory overrides." >&2
                exit 1
            fi
        fi
    fi
fi

BINDIR="${BINDIR:-/usr/local/bin}"
CONFDIR="${CONFDIR:-/etc/yip}"
SYSD_DIR="${SYSD_DIR:-/etc/systemd/system}"
OPENRC_DIR="${OPENRC_DIR:-/etc/init.d}"
RUNIT_DIR="${RUNIT_DIR:-/etc/sv}"
INIT_SYSTEM="${INIT_SYSTEM:-auto}"
REPO="${REPO:-femboyisp/yip}"

# --- 2. OS & Architecture Check ---
OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
    echo "Error: Unsupported OS '$OS'. yip binaries are built for Linux." >&2
    exit 1
fi

if [ -z "$TARGET" ]; then
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64)
            TARGET="x86_64-unknown-linux-musl"
            ;;
        aarch64|arm64)
            TARGET="aarch64-unknown-linux-musl"
            ;;
        *)
            echo "Error: Unsupported architecture '$ARCH'. Only x86_64/amd64 and aarch64/arm64 are supported." >&2
            exit 1
            ;;
    esac
fi

# --- 3. Temp Directory & Cleanup ---
TMPDIR="$(mktemp -d 2>/dev/null || echo "/tmp/yip-install-$$")"
[ ! -d "$TMPDIR" ] && mkdir -p "$TMPDIR"
cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM HUP

# --- 4. Download & Verification ---
download() {
    _url="$1"
    _dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$_url" -o "$_dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$_dest" "$_url"
    else
        echo "Error: Neither 'curl' nor 'wget' found. Cannot download release." >&2
        exit 1
    fi
}

CHECKSUMS_FILE=""

if [ -n "$LOCAL_TARBALL" ]; then
    if [ ! -f "$LOCAL_TARBALL" ]; then
        echo "Error: LOCAL_TARBALL '$LOCAL_TARBALL' not found." >&2
        exit 1
    fi
    TARBALL_PATH="$LOCAL_TARBALL"
    TARBALL_FILE="$(basename "$LOCAL_TARBALL")"

    if [ -n "$LOCAL_SHA256SUMS" ]; then
        if [ ! -f "$LOCAL_SHA256SUMS" ]; then
            echo "Error: LOCAL_SHA256SUMS '$LOCAL_SHA256SUMS' not found." >&2
            exit 1
        fi
        CHECKSUMS_FILE="$LOCAL_SHA256SUMS"
    elif [ -f "${LOCAL_TARBALL}.sha256" ]; then
        CHECKSUMS_FILE="${LOCAL_TARBALL}.sha256"
    elif [ -f "$(dirname "$LOCAL_TARBALL")/SHA256SUMS" ]; then
        CHECKSUMS_FILE="$(dirname "$LOCAL_TARBALL")/SHA256SUMS"
    fi
else
    # Live download from GitHub releases
    VERSION="${VERSION:-latest}"
    if [ "$VERSION" = "latest" ]; then
        echo "Resolving latest release for ${REPO}..."
        TAG=""
        if command -v curl >/dev/null 2>&1; then
            REDIRECT_URL="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" 2>/dev/null | tr -d '\r')"
            TAG="${REDIRECT_URL##*/}"
            if [ "$TAG" = "latest" ] || [ -z "$TAG" ]; then
                TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/')"
            fi
        elif command -v wget >/dev/null 2>&1; then
            TAG="$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/')"
        fi

        if [ -z "$TAG" ] || [ "$TAG" = "latest" ]; then
            echo "Error: Could not resolve latest release tag for ${REPO}." >&2
            exit 1
        fi
    else
        case "$VERSION" in
            v*) TAG="$VERSION" ;;
            *)  TAG="v$VERSION" ;;
        esac
    fi

    TARBALL_FILE="yip-${TAG}-${TARGET}.tar.gz"
    TARBALL_URL="https://github.com/${REPO}/releases/download/${TAG}/${TARBALL_FILE}"
    CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS"

    TARBALL_PATH="$TMPDIR/$TARBALL_FILE"
    CHECKSUMS_FILE="$TMPDIR/SHA256SUMS"

    echo "Downloading ${TARBALL_URL}..."
    download "$TARBALL_URL" "$TARBALL_PATH"
    echo "Downloading ${CHECKSUMS_URL}..."
    download "$CHECKSUMS_URL" "$CHECKSUMS_FILE"
fi

# Verify Checksum
if [ -n "$CHECKSUMS_FILE" ]; then
    echo "Verifying SHA-256 checksum..."
    EXPECTED_HASH=""

    # 1. Match basename in checksum file
    MATCH_LINE="$(grep -E "[[:space:]]\*?${TARBALL_FILE}\$" "$CHECKSUMS_FILE" 2>/dev/null | head -n 1)"
    if [ -n "$MATCH_LINE" ]; then
        EXPECTED_HASH="$(printf '%s\n' "$MATCH_LINE" | awk '{print $1}')"
    fi

    # 2. Match target triple in checksum file
    if [ -z "$EXPECTED_HASH" ]; then
        MATCH_LINE="$(grep -E "${TARGET}" "$CHECKSUMS_FILE" 2>/dev/null | head -n 1)"
        if [ -n "$MATCH_LINE" ]; then
            EXPECTED_HASH="$(printf '%s\n' "$MATCH_LINE" | awk '{print $1}')"
        fi
    fi

    # 3. Match single 64-hex entry
    if [ -z "$EXPECTED_HASH" ]; then
        FIRST_WORD="$(awk '{print $1}' "$CHECKSUMS_FILE" 2>/dev/null | head -n 1)"
        case "$FIRST_WORD" in
            [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]*)
                if [ ${#FIRST_WORD} -eq 64 ]; then
                    EXPECTED_HASH="$FIRST_WORD"
                fi
                ;;
        esac
    fi

    if [ -z "$EXPECTED_HASH" ]; then
        echo "Error: Could not locate checksum for $TARBALL_FILE in $CHECKSUMS_FILE." >&2
        exit 1
    fi

    CHECK_TMP="$TMPDIR/sha256_check.txt"
    TARBALL_BASENAME="$(basename "$TARBALL_PATH")"
    TARBALL_DIR="$(dirname "$TARBALL_PATH")"
    printf '%s  %s\n' "$EXPECTED_HASH" "$TARBALL_BASENAME" > "$CHECK_TMP"

    VERIFIED=0
    if command -v sha256sum >/dev/null 2>&1; then
        if (cd "$TARBALL_DIR" && sha256sum -c "$CHECK_TMP" >/dev/null 2>&1); then
            VERIFIED=1
        fi
    elif command -v shasum >/dev/null 2>&1; then
        if (cd "$TARBALL_DIR" && shasum -a 256 -c "$CHECK_TMP" >/dev/null 2>&1); then
            VERIFIED=1
        fi
    else
        echo "Error: Neither 'sha256sum' nor 'shasum' found. Checksum verification unavailable." >&2
        exit 1
    fi

    if [ "$VERIFIED" -ne 1 ]; then
        echo "Error: Checksum verification failed for $TARBALL_FILE." >&2
        exit 1
    fi
    echo "Checksum OK ($EXPECTED_HASH)"
fi

# --- 5. Extraction & Binary Installation ---
EXTRACT_DIR="$TMPDIR/extract"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$TARBALL_PATH" -C "$EXTRACT_DIR"

ROOT_DIR=""
if [ -f "$EXTRACT_DIR/yipd" ] && [ -f "$EXTRACT_DIR/yip-ca" ] && [ -f "$EXTRACT_DIR/yip-rendezvous" ]; then
    ROOT_DIR="$EXTRACT_DIR"
else
    # Find candidate directory containing all required binaries (distinguishes binary dir from contrib/openrc/yipd)
    for cand in $(find "$EXTRACT_DIR" -type f -name "yip-ca" 2>/dev/null); do
        cand_dir="$(dirname "$cand")"
        if [ -f "$cand_dir/yipd" ] && [ -f "$cand_dir/yip-rendezvous" ]; then
            ROOT_DIR="$cand_dir"
            break
        fi
    done
fi

if [ -z "$ROOT_DIR" ]; then
    echo "Error: Required binaries (yipd, yip-ca, yip-rendezvous) not found in release archive." >&2
    exit 1
fi

# Verify required binaries exist
for bin in yipd yip-ca yip-rendezvous; do
    if [ ! -f "$ROOT_DIR/$bin" ]; then
        echo "Error: Required binary '$bin' missing from release archive." >&2
        exit 1
    fi
done

# Install binaries
echo "Installing binaries to ${BINDIR}..."
$SUDO mkdir -p "$BINDIR"
for bin in yipd yip-ca yip-rendezvous; do
    $SUDO cp "$ROOT_DIR/$bin" "$BINDIR/$bin"
    $SUDO chmod 0755 "$BINDIR/$bin"
done

# --- 6. Configuration Seeding ---
echo "Seeding configuration into ${CONFDIR}..."
$SUDO mkdir -p "$CONFDIR"
if [ -f "$ROOT_DIR/example.config" ]; then
    $SUDO cp "$ROOT_DIR/example.config" "$CONFDIR/yipd.conf.example"
    $SUDO chmod 0644 "$CONFDIR/yipd.conf.example"
fi

# --- 7. Init System Detection & Installation ---
DETECTED_INIT="none"
case "$INIT_SYSTEM" in
    auto|"")
        if [ -d /run/systemd/system ]; then
            DETECTED_INIT="systemd"
        elif command -v rc-service >/dev/null 2>&1 || [ -d /run/openrc ]; then
            DETECTED_INIT="openrc"
        elif command -v runsv >/dev/null 2>&1 || [ -d /etc/sv ]; then
            DETECTED_INIT="runit"
        elif [ -d /etc/systemd/system ]; then
            DETECTED_INIT="systemd"
        elif [ -d /etc/init.d ]; then
            DETECTED_INIT="openrc"
        else
            DETECTED_INIT="none"
        fi
        ;;
    systemd|openrc|runit|none)
        DETECTED_INIT="$INIT_SYSTEM"
        ;;
    *)
        echo "Error: Unknown INIT_SYSTEM '$INIT_SYSTEM'. Expected auto, systemd, openrc, runit, or none." >&2
        exit 1
        ;;
esac

echo "Configuring init service: ${DETECTED_INIT}"
case "$DETECTED_INIT" in
    systemd)
        $SUDO mkdir -p "$SYSD_DIR"
        if [ -f "$ROOT_DIR/contrib/systemd/yipd.service" ]; then
            $SUDO cp "$ROOT_DIR/contrib/systemd/yipd.service" "$SYSD_DIR/yipd.service"
            $SUDO chmod 0644 "$SYSD_DIR/yipd.service"
            echo "Installed ${SYSD_DIR}/yipd.service"
        fi
        if [ -f "$ROOT_DIR/contrib/systemd/yip-rendezvous.service" ]; then
            $SUDO cp "$ROOT_DIR/contrib/systemd/yip-rendezvous.service" "$SYSD_DIR/yip-rendezvous.service"
            $SUDO chmod 0644 "$SYSD_DIR/yip-rendezvous.service"
            echo "Installed ${SYSD_DIR}/yip-rendezvous.service"
        fi
        if [ -d /run/systemd/system ] && [ "$SYSD_DIR" = "/etc/systemd/system" ] && command -v systemctl >/dev/null 2>&1; then
            echo "Reloading systemd daemon..."
            $SUDO systemctl daemon-reload 2>/dev/null || true
        fi
        ;;
    openrc)
        $SUDO mkdir -p "$OPENRC_DIR"
        if [ -f "$ROOT_DIR/contrib/openrc/yipd" ]; then
            $SUDO cp "$ROOT_DIR/contrib/openrc/yipd" "$OPENRC_DIR/yipd"
            $SUDO chmod 0755 "$OPENRC_DIR/yipd"
            echo "Installed ${OPENRC_DIR}/yipd"
        fi
        if [ -f "$ROOT_DIR/contrib/openrc/yip-rendezvous" ]; then
            $SUDO cp "$ROOT_DIR/contrib/openrc/yip-rendezvous" "$OPENRC_DIR/yip-rendezvous"
            $SUDO chmod 0755 "$OPENRC_DIR/yip-rendezvous"
            echo "Installed ${OPENRC_DIR}/yip-rendezvous"
        fi
        ;;
    runit)
        $SUDO mkdir -p "$RUNIT_DIR"
        if [ -d "$ROOT_DIR/contrib/runit/yipd" ]; then
            $SUDO mkdir -p "$RUNIT_DIR/yipd/log"
            $SUDO cp "$ROOT_DIR/contrib/runit/yipd/run" "$RUNIT_DIR/yipd/run"
            $SUDO chmod 0755 "$RUNIT_DIR/yipd/run"
            if [ -f "$ROOT_DIR/contrib/runit/yipd/log/run" ]; then
                $SUDO cp "$ROOT_DIR/contrib/runit/yipd/log/run" "$RUNIT_DIR/yipd/log/run"
                $SUDO chmod 0755 "$RUNIT_DIR/yipd/log/run"
            fi
            echo "Installed ${RUNIT_DIR}/yipd"
        fi
        if [ -d "$ROOT_DIR/contrib/runit/yip-rendezvous" ]; then
            $SUDO mkdir -p "$RUNIT_DIR/yip-rendezvous/log"
            $SUDO cp "$ROOT_DIR/contrib/runit/yip-rendezvous/run" "$RUNIT_DIR/yip-rendezvous/run"
            $SUDO chmod 0755 "$RUNIT_DIR/yip-rendezvous/run"
            if [ -f "$ROOT_DIR/contrib/runit/yip-rendezvous/log/run" ]; then
                $SUDO cp "$ROOT_DIR/contrib/runit/yip-rendezvous/log/run" "$RUNIT_DIR/yip-rendezvous/log/run"
                $SUDO chmod 0755 "$RUNIT_DIR/yip-rendezvous/log/run"
            fi
            echo "Installed ${RUNIT_DIR}/yip-rendezvous"
        fi
        ;;
    none)
        echo "Skipping service unit installation (INIT_SYSTEM=none)."
        ;;
esac

echo ""
echo "Installation complete!"
echo "Binaries: $BINDIR/{yipd, yip-ca, yip-rendezvous}"
echo "Config:   $CONFDIR/yipd.conf.example"
if [ ! -f "$CONFDIR/yipd.conf" ]; then
    echo "To configure yip, copy $CONFDIR/yipd.conf.example to $CONFDIR/yipd.conf and edit."
fi
