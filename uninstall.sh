#!/usr/bin/env bash
set -euo pipefail

systemctl --user disable --now blueripple-passkey.service 2>/dev/null || true
systemctl --user disable --now authentik-biometric.service 2>/dev/null || true
rm -f -- "$HOME/.config/systemd/user/blueripple-passkey.service"
rm -f -- "$HOME/.config/systemd/user/authentik-biometric.service"
rm -f -- "$HOME/.local/bin/blueripple-passkey"
rm -f -- "$HOME/.local/bin/authentik-biometric"
systemctl --user daemon-reload

echo "BlueRipple Passkey was removed."
echo "Passkey metadata and configuration were preserved in:"
echo "  $HOME/.local/share/blueripple-passkey"
echo "  $HOME/.config/blueripple-passkey"
echo "Legacy data, if present, was also kept under authentik-biometric directories."
echo "The root-owned udev/module files were preserved so uninstall does not unexpectedly revoke device access."
