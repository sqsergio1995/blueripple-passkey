#!/usr/bin/env bash
set -euo pipefail

systemctl --user disable --now authentik-biometric.service 2>/dev/null || true
rm -f -- "$HOME/.config/systemd/user/authentik-biometric.service"
rm -f -- "$HOME/.local/bin/authentik-biometric"
systemctl --user daemon-reload

echo "Authentik BioKey was removed."
echo "Passkey metadata and configuration were preserved in:"
echo "  $HOME/.local/share/authentik-biometric"
echo "  $HOME/.config/authentik-biometric"
echo "The root-owned udev/module files were preserved so uninstall does not unexpectedly revoke device access."
