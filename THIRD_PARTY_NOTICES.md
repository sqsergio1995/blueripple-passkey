# Third-party notices

BlueRipple Passkey is derived from Peter Sanford's `tpm-fido` and the
`mc256/tpm-fido2-thinkpad-linux` fork at commit
`49222c60dbbf0c5ec4356240cbd92789e41945da`.

- Original project: https://github.com/psanford/tpm-fido
- Biometric/FIDO2 fork: https://github.com/mc256/tpm-fido2-thinkpad-linux

The retained source is distributed under the MIT License in `LICENSE`.
BlueRipple Passkey is an independent community project and is not affiliated
with or endorsed by Authentik Security Inc.

## Go module dependencies

The application also uses the following Go modules. Their complete license
texts are included in each module's source distribution and remain available
through the linked upstream repositories.

| Module | Version | License |
| --- | --- | --- |
| [fyne.io/systray](https://github.com/fyne-io/systray) | v1.12.2 | Apache-2.0 |
| [github.com/fxamacker/cbor/v2](https://github.com/fxamacker/cbor) | v2.9.3 | MIT |
| [github.com/google/go-tpm](https://github.com/google/go-tpm) | v0.3.3 | Apache-2.0 |
| [github.com/psanford/uhid](https://github.com/psanford/uhid) | 2021-05-16 revision | BSD-3-Clause |
| [github.com/godbus/dbus/v5](https://github.com/godbus/dbus) | v5.1.0 | BSD-2-Clause |
| [github.com/x448/float16](https://github.com/x448/float16) | v0.8.4 | MIT |
| [golang.org/x/sys](https://go.googlesource.com/sys) | v0.44.0 | BSD-3-Clause |

Go itself is distributed under a BSD-3-Clause license. Copyright and license
notices must be preserved when redistributing source or binary bundles. This
inventory is generated from `go.mod`; update it whenever dependencies change.
