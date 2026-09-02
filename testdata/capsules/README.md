# Capsule fixtures

A capsule written by this package, with the key that opens it:

| File | Container |
|---|---|
| `kycap2.kycap` | `kycap/2` — JSON manifest bound in as AAD, base64 ciphertext, nonce prefixed |

This key protects fixture data and nothing else. It is committed on purpose: a golden
capsule whose key is withheld cannot prove that a capsule written before a change still
opens after it.

Regenerate only if the container format changes deliberately. A change that stops this
opening is a breaking change to every backup already on disk.

## What used to be here

`kysignon.kycap` (`kycap/1`) and `kyrecovery.kycap` (a tar of `manifest.json`, `nonce.bin`
and `payload.enc`) were real output from `kysignon-server` and `kyrecovery-server`. Both
containers authenticated their ciphertext and left the manifest outside the AEAD — `kycap/1`
entirely, the tar container everything but its own `aad` string — so `capsule_id`,
`service_name`, `threshold`, `total_shares` and the verification recipe could be rewritten
by anyone who could reach the file, without the key.

Neither server needs its old capsules read, so the readers were retired rather than kept
half-trusted. `ky_server_base` and `gridlock-server` contributed no fixture because they
persisted no capsule.
