# ky-primitives

Shared security primitives for the Busness.app suite. Standard library only, no
dependencies, ever — `TestModuleHasNoDependencies` fails the build if `go.mod` ever grows a
`require`, because a module heavier than the standard library is one `kysignon-server`
cannot take.

A primitive belongs here when the suite's copies of it disagree in a way that silently
corrupts or loses recovery data. Duplicated HTTP, session and header code across the suite
is real security debt, but it is per-product configuration rather than a durable format, so
it is fixed in place rather than moved here.

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

## shamir

Splits a secret into custodian shares and reconstructs it.

The suite carried two implementations over **two different GF(2^8) fields** — 0x11d in
`ky_server_base`, `gridlock-server` and `kysignon-server`, 0x11b in `kyrecovery-server`.
63232 of the 65536 products in their multiplication tables disagree, so shares written by
one reconstruct a different secret through the other, with a nil error.

It stayed hidden because shares 1, 2 and 3 make every Lagrange coefficient 1. The combine
degenerates to XOR and agrees in any field — and those are the shares a round-trip test
reaches for first. `TestRoundTripEveryIndexSubset` covers all ten 3-of-5 subsets for that
reason.

This package uses 0x11b, the AES field, pinned by golden vectors derived by hand rather
than read off the implementation. Nothing was in the wild, so the choice was free.

Arithmetic is branch-free and table-free. Both predecessors indexed exp/log tables with
share bytes, which are the secret; this one multiplies with shifts and masks and inverts by
exponentiation, so no memory access depends on a secret value. A split is not a hot path.

The 0x11d copies also had three ways to fail on a malformed share, all reachable from
`kyrestore`'s repeated `-shard` flag — a custodian retrying mid-disaster:

| Input to `Combine` | 0x11d copies | here |
|---|---|---|
| Same share twice | panic, `divide by zero in GF(256)` | `ErrDuplicateIndex` |
| Truncated share | panic, index out of range | `ErrShareLength` |
| Share at index 0 | all-zero secret, nil error | `ErrShareIndex` |

`FuzzCombineNeverPanics` holds that line. Distinct non-zero indices make every Lagrange
denominator non-zero, so no input can divide by zero however malformed.

`Split` resamples a zero leading coefficient. Without it the polynomial's degree drops and
fewer shares than promised recover that byte, once every 256 draws.

```go
shares, err := shamir.Split(key, 3, 5)   // any 3 of 5
secret, err := shamir.Combine(shares)     // every share given is used
card := shares[0].String()                // "1-a1b2..." for a custodian card
```

`Combine` takes no threshold. A share carries no record of what the threshold was, so too
few shares reconstruct a wrong secret whatever you pass — an argument that cannot make the
answer safer is one more thing to get wrong. Bind a hash of the plaintext alongside
instead; `capsule`'s payload hash is exactly that check, and it is what currently turns a
cross-field reconstruction into `ErrCorruptCapsule` rather than a garbage key.

## auditchain

Builds and verifies a tamper-evident hash chain over audit records.

Three implementations existed, with three tuple layouts and three key policies:

| | `kypassword-server` | `kybookmarks-server` | `kyrecovery-server` |
|---|---|---|---|
| Key | generated, ≥32 bytes enforced | **falls back to a literal in its own source** | HKDF from the keyring |
| Truncation | anchor beside the key | undetectable | sequence numbers in the DB |
| Fields | joined on bare `\|` | joined on bare `\|` | details pre-hashed |

`kybookmarks-server/internal/audit/audit.go:44` substitutes
`"kybookmarks-audit-default-secret"` when no key is configured, so an unconfigured
deployment ships a chain anyone can recompute from the repository — and `VerifyChain` still
passes. The key floor here is 32 bytes and there is no fallback.

Every field is length-prefixed. Joining on a delimiter lets a field containing it shift
into its neighbour and produce another record's digest, forging a record without the key;
`TestFieldsAreUnambiguousAcrossDelimiters` pins that.

`Verify` requires the `Anchor` — a count and head hash kept outside the log. Hashes alone
cannot catch a log with records removed from the end, because what remains still chains
correctly, so the anchor is a parameter rather than an option.

```go
chain, err := auditchain.New(key)          // or Resume(key, lastRecord)
rec, err := chain.Append("login", user)    // persist rec, and chain.Anchor() beside it
err = auditchain.Verify(key, records, anchor)
```

`Fields` are opaque and storage is not this package's business. The three implementations
logged different things and wrote to JSON lines, a file and a database; forcing one schema
on them is what made them diverge, and where the bytes went was never the part that broke.
