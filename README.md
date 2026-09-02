# ky-primitives

Shared security primitives for the Busness.app suite. Standard library only, no
dependencies, ever.

## capsule

Reads and writes the suite's encrypted backup containers.

Two containers hold real recovery data on disk, and they cannot read each other:

| Container | Written by | Shape |
|---|---|---|
| `kycap/1` | `kysignon-server` | JSON object, base64 ciphertext string, nonce prefixed |
| tar | `kyrecovery-server` | tar of `manifest.json`, `nonce.bin`, `payload.enc`, AAD-bound |

`Open` reads both and always will — dropping either orphans backups already on disk.
`Seal` writes `kycap/1` only, so the suite stops accumulating formats.

```go
files, err := capsule.Open(raw, key, "/var/restore")   // either container
raw, key, err := capsule.Seal(name, version, files, nil, nil, 2, 3)
```

`key` is raw bytes, never a hex string. The suite's implementations disagreed on that and
bytes is the one that cannot be got wrong silently: a hex string of the right length is a
valid 64-byte key that decrypts to garbage.

### Extraction hardening

Both containers decrypt to a gzipped tar, so one hardened extraction serves both. It is
ported from `kysignon-server`, which carried the strongest version in the suite, and it
means a `kyrecovery-server` capsule opened here gets checks its own `Unpack` never applied.

Refused: path traversal, absolute paths, backslash separators, NUL bytes, symlinks,
hardlinks, directories, device nodes, FIFOs, archives over 8 GiB expanded, members over
4 GiB, more than 4096 files, and any restore into a non-empty directory. File modes are
clamped to owner-only — a restored capsule carries signing keys, and an archive header is
attacker-controlled.

Every one of those is covered by a test in `capsule/hardening_test.go`. None is asserted
without one.

### Fixtures

`testdata/capsules/` holds one real capsule from each persisted container, with the key
that opens it. See the README there for why the keys are committed.

`ky_server_base` and `gridlock-server` contribute no fixture because they persist no
capsule at all — see `ky_server_base/docs/capsule-interop-findings.md`.
