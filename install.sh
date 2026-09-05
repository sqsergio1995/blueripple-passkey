#!/usr/bin/env bash
set -euo pipefail

APP_NAME="blueripple-passkey"
AUTHENTIK_URL=""
RP_ID=""
NO_START=0

usage() {
    echo "Usage: ./install.sh --authentik-url https://auth.example.com [--no-start]"
    echo "       ./install.sh --rp-id auth.example.com [--no-start]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --authentik-url)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            AUTHENTIK_URL="$2"
            shift 2
            ;;
        --rp-id)
            [[ $# -ge 2 ]] || { usage; exit 2; }
            RP_ID="$2"
            shift 2
            ;;
        --no-start)
            NO_START=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if [[ -n "$AUTHENTIK_URL" && -n "$RP_ID" ]]; then
    echo "Use either --authentik-url or --rp-id, not both." >&2
    exit 2
fi

if [[ -n "$AUTHENTIK_URL" ]]; then
    command -v python3 >/dev/null || { echo "python3 is required to validate the URL." >&2; exit 1; }
    RP_ID="$(python3 -c 'import sys, urllib.parse; u=urllib.parse.urlparse(sys.argv[1]); ok=u.scheme=="https" and bool(u.hostname) and not u.username and not u.password and not u.path.rstrip("/") and not u.query and not u.fragment; print(u.hostname.lower()) if ok else sys.exit(2)' "$AUTHENTIK_URL")" || {
        echo "authentik URL must look like https://auth.example.com with no path, query, or credentials." >&2
        exit 2
    }
fi

if [[ -z "$RP_ID" || "$RP_ID" == *"://"* || "$RP_ID" == *"/"* || "$RP_ID" == *":"* || "$RP_ID" == *"*"* || "$RP_ID" =~ [[:space:]] ]]; then
    echo "A valid authentik hostname is required. Example: --authentik-url https://auth.example.com" >&2
    exit 2
fi

for command_name in install sudo systemctl fprintd-list fprintd-verify notify-send; do
    command -v "$command_name" >/dev/null || {
        echo "Missing required command: $command_name" >&2
        exit 1
    }
done

if [[ ! -e /dev/tpmrm0 ]]; then
    echo "No TPM 2.0 resource manager found at /dev/tpmrm0." >&2
    exit 1
fi

if ! fprintd-list "$(id -un)" >/dev/null 2>&1; then
    echo "No enrolled fingerprint was found. Run fprintd-enroll, then retry." >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf -- "$BUILD_DIR"' EXIT

PREBUILT="$SCRIPT_DIR/dist/blueripple-passkey-linux-amd64"
if [[ "$(uname -m)" == "x86_64" && -x "$PREBUILT" ]]; then
    echo "Using the included BlueRipple Passkey binary..."
    if [[ -f "$SCRIPT_DIR/dist/SHA256SUMS" ]]; then
        (cd "$SCRIPT_DIR/dist" && sha256sum --check --status SHA256SUMS) || {
            echo "The included binary failed its checksum." >&2
            exit 1
        }
    fi
    install -m 0755 "$PREBUILT" "$BUILD_DIR/$APP_NAME"
else
    command -v go >/dev/null || {
        echo "No compatible prebuilt binary was found and Go is not installed." >&2
        exit 1
    }
    echo "Building BlueRipple Passkey..."
    (
        cd "$SCRIPT_DIR"
        CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BUILD_DIR/$APP_NAME" ./main.go
    )
fi

install -d -m 0755 "$HOME/.local/bin"
install -m 0755 "$BUILD_DIR/$APP_NAME" "$HOME/.local/bin/$APP_NAME"

install -d -m 0700 "$HOME/.config/blueripple-passkey"
install -d -m 0700 "$HOME/.local/share/blueripple-passkey"
printf 'BLUERIPPLE_PASSKEY_RP_IDS=%s\n' "${RP_ID,,}" > "$HOME/.config/blueripple-passkey/config.env"
chmod 0600 "$HOME/.config/blueripple-passkey/config.env"

install -d -m 0755 "$HOME/.config/systemd/user"
install -m 0644 "$SCRIPT_DIR/contrib/blueripple-passkey.service" "$HOME/.config/systemd/user/blueripple-passkey.service"

# Retire the pre-rename user service and executable, if present. Credential
# metadata is migrated by BlueRipple Passkey on first launch.
systemctl --user disable --now authentik-biometric.service 2>/dev/null || true
rm -f -- "$HOME/.config/systemd/user/authentik-biometric.service"
rm -f -- "$HOME/.local/bin/authentik-biometric"

echo "Installing the UHID access rule (administrator permission required)..."
sudo install -m 0644 "$SCRIPT_DIR/contrib/90-blueripple-passkey-uhid.rules" /etc/udev/rules.d/90-blueripple-passkey-uhid.rules
sudo install -m 0644 "$SCRIPT_DIR/contrib/uhid.conf" /etc/modules-load.d/blueripple-passkey-uhid.conf
sudo modprobe uhid
sudo udevadm control --reload-rules
sudo udevadm trigger

if [[ ! -r /dev/tpmrm0 || ! -w /dev/tpmrm0 ]]; then
    echo "Your user cannot access /dev/tpmrm0 yet." >&2
    if getent group tss >/dev/null 2>&1; then
        echo "Adding $(id -un) to the tss group. Log out and back in before starting BlueRipple Passkey." >&2
        sudo usermod -aG tss "$(id -un)"
    else
        echo "Grant TPM access using your distribution's TPM/udev policy, then log in again." >&2
    fi
    NO_START=1
fi

systemctl --user daemon-reload
if [[ "$NO_START" -eq 0 ]]; then
    BLUERIPPLE_PASSKEY_RP_IDS="${RP_ID,,}" "$HOME/.local/bin/blueripple-passkey" --check
    systemctl --user enable --now blueripple-passkey.service
    echo "BlueRipple Passkey is installed and running for ${RP_ID,,}."
else
    systemctl --user enable blueripple-passkey.service
    echo "BlueRipple Passkey is installed. After logging in again, run:"
    echo "  systemctl --user start blueripple-passkey.service"
fi

echo "Next: import authentik/blueripple-passkey.yaml in authentik and enroll this passkey."
