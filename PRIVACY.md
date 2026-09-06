# Privacy

BlueRipple Passkey is a local Linux application. It does not operate a cloud
service, include analytics, or send telemetry to Blue Ripple Prime.

## Fingerprint data

BlueRipple Passkey does not read, receive, store, or transmit fingerprint
images or biometric templates. It asks the operating system's `fprintd`
service to perform a verification and receives only success or failure. The
fingerprint reader, its firmware, `fprintd`, and the operating system control
enrollment and template storage.

## Data stored on the device

For discoverable WebAuthn credentials, the application stores the following in
`~/.local/share/blueripple-passkey/credentials.json`:

- the configured authentik relying-party hostname and display label;
- the authentik user identifier and account display labels;
- the public credential key and opaque TPM credential handle; and
- the credential creation time.

The file is restricted to the current user (`0600`) and its directory is
restricted to that user (`0700`). Private signing keys are created by and
remain bound to the TPM. The metadata is not uploaded by this project.

The configured authentik host is stored in
`~/.config/blueripple-passkey/config.env`, also with mode `0600`.

## Logs and network activity

Service logs contain operational events, error categories, the configured
relying-party hostname, and message sizes. They do not intentionally contain
fingerprint data, credential identifiers, WebAuthn challenges, usernames, or
account display names.

BlueRipple Passkey does not make outbound network connections. The browser
communicates with authentik over HTTPS and with the local virtual FIDO device;
those communications are governed by the browser and authentik deployment.

## Deletion

`uninstall.sh` removes the application and service but intentionally preserves
configuration and credential metadata to prevent accidental lockout. After
removing the corresponding WebAuthn credentials from authentik, a user may
delete these local directories manually:

```text
~/.local/share/blueripple-passkey
~/.config/blueripple-passkey
```

Deleting local metadata does not remove a credential from authentik. Delete it
from authentik first and retain a tested recovery method.

## Scope

This statement covers the open-source desktop application only. A website,
package host, Linux distribution, browser, fingerprint stack, or authentik
instance may have separate data practices.

