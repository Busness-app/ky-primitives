# Capsule fixtures

One real capsule from each container the suite actually persists, with the key that
opens it:

| File | Written by | Container |
|---|---|---|
| `kysignon.kycap` | `kysignon-server` `CreateCapsule` + `SerializeCapsule` | JSON, `kycap/1` |
| `kyrecovery.kycap` | `kyrecovery-server` `capsule.Pack` | tar: `manifest.json`, `nonce.bin`, `payload.enc` |

These keys protect fixture data and nothing else. They are committed on purpose: a golden
capsule whose key is withheld cannot prove that a capsule written before a migration still
opens after it.

`ky_server_base` and `gridlock-server` contribute no fixture because they persist no
capsule — see `ky_server_base/docs/capsule-interop-findings.md`.

Regenerate these only if a container format changes deliberately. A change that stops one
of them opening is a breaking change to every backup already on disk.
