# Threat model

## Security goals

BlueRipple Passkey is intended to provide phishing-resistant WebAuthn login to
an explicitly configured authentik hostname, keep credential private keys
non-exportable from the device TPM, and require a successful local fingerprint
verification before this application creates or returns an assertion.

It also minimizes exposure by making no outbound network connections, rejecting
unconfigured relying-party IDs, declining secret-derivation extensions, and
storing local metadata with user-only permissions.

## Trust boundaries

```text
authentik <--- HTTPS ---> browser <--- CTAP2/UHID ---> BlueRipple Passkey
                                                        |          |
                                                        v          v
                                                       TPM       fprintd
```

The authentik server controls accounts, WebAuthn challenges, sessions, policy,
and recovery. The browser validates HTTPS origins and maps WebAuthn origins to
relying-party IDs. BlueRipple Passkey enforces an exact local RP-ID allowlist,
requests fingerprint verification from `fprintd`, and asks the TPM to perform
credential-key operations.

## Protected assets

- TPM-bound WebAuthn private keys;
- local credential handles and account labels;
- the integrity of the relying-party allowlist;
- the user's authentik account and recovery methods; and
- the truth of the user-present and user-verified flags in assertions.

## In-scope threats

- a remote phishing site requesting credentials for an unconfigured RP ID;
- malformed or oversized CTAP2/HID messages from the local browser;
- accidental disclosure of account labels or credential material in logs;
- permissive local metadata-file permissions; and
- user-writable `PATH` entries substituting a fake fingerprint command.

## Out-of-scope threats and limitations

- compromise of root, the kernel, the logged-in Linux account, the browser,
  `fprintd`, fingerprint-reader firmware, TPM firmware, or authentik;
- physical coercion, fingerprint spoofing, denial of service, and hardware
  failure;
- recovery from a TPM clear, motherboard replacement, or deleted metadata;
- malware running as the same user with access to both the TPM device and local
  credential handles; and
- guarantees provided by certified commercial authenticators.

The fingerprint check is an application-level gate. It is not cryptographically
bound into a TPM policy session. Consequently, this design protects against
remote credential theft and ordinary phishing but must not be represented as
protecting a user whose local account or trusted computing base is compromised.

## Recovery requirements

Before enrollment, retain at least one independent authentik recovery method,
such as offline recovery codes or a separate hardware security key. Test it in
a private browser session. Do not remove an existing factor until both the new
login and recovery path have succeeded.

