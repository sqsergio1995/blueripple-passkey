# Security policy

BlueRipple Passkey is experimental security software. It has not completed an
independent security audit or FIDO certification and should be evaluated before
production use.

## Supported versions

Until the first stable release, security fixes are made on the latest `main`
branch and the newest beta release only. Older commits and prereleases are not
supported.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security-advisory form:

https://github.com/sqsergio1995/blueripple-passkey/security/advisories/new

Include the affected version, Linux distribution, impact, reproduction steps,
and a minimal proof of concept. Do not include real fingerprints, recovery
codes, private keys, credential files, or production account data.

The maintainer will acknowledge a report when practical, investigate it, and
coordinate disclosure and a fix based on severity. No response-time guarantee
is offered for this volunteer project.

## Security assumptions

- Keep a tested authentik recovery method before enrolling or changing flows.
- Install only from an official project source and verify published checksums.
  Verify a release signature as well whenever one is provided.
- Treat the local user account, root, kernel, TPM firmware, `fprintd`, browser,
  and authentik server as trusted components.
- The fingerprint prompt is enforced by this local application and `fprintd`;
  it is not a TPM authorization policy. A compromised local account is outside
  the protection boundary.
- Only exact, explicitly configured authentik hostnames are accepted.

See `THREAT_MODEL.md` for the detailed trust boundaries and `PRIVACY.md` for
local data handling.
