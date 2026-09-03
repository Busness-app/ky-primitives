# The suite recovery keypair, and sealing a capsule to it

Design, 2026-09-03. No implementation.

`capsule.Seal` mints a random AES-256 key per capsule and hands it back for the caller to
split. Under the model decided on 2026-09-03 — each product seals and restores its own
capsule, kyrecovery stores ciphertext blind — that key would be split into custodian shares
on every backup, which is a ceremony per night. This document replaces the per-capsule key
with one long-lived recovery keypair for the suite, and makes `capsule` seal to its public
key so that no product ever holds a secret that opens a backup.

The decisions this rests on are recorded in `2026-09-02-suite-migration-design.md` under
"Decisions taken" and "One suite-wide recovery keypair". This document does not re-argue
them.

## Non-goals

- **Key rotation.** The key ID in the manifest is what makes rotation possible later
  without a format change. Nothing here performs one.
- **The share relay.** How custodian shares reach a recovering product through kyrecovery
  is Plan 5. This document fixes what a share *is* and nothing about how it travels.
- **Kyrecovery's ceremony UI, its key ID pin, and the product-side pairing receive path.**
  All three consume the API below. None of them shapes it.
- **Sender authentication.** Anyone holding the public key can mint a capsule that opens.
  Decided 2026-09-03: authenticity comes from the authenticated deposit channel and
  kyrecovery's unchanged-since-deposit record, not from the container. Recorded so the
  property is not mistaken for an oversight.

---

## Decisions this design makes

| Decision | Why |
|---|---|
| The public-key form **replaces** raw-key `Seal` and `Open`; nothing returns or accepts a data key | One way to seal is one thing to get right. A surviving raw-key path is the per-capsule-share model with a different name. Nothing is in the wild. |
| HPKE from the Go 1.26 standard library, not a hand-rolled key schedule | `crypto/hpke` is public API as of Go 1.26 (`api/go1.26.txt`), which is this module's floor. Go pins it to the RFC 9180 and draft-ietf-hpke-pq vectors. Zero new dependencies. |
| KEM is X-Wing, `hpke.MLKEM768X25519`, id `0x647a` | Backups are the artefact most likely to still matter when a recorded ciphertext is attacked. Decided 2026-09-03 over X25519 alone. |
| AEAD is **AES-256-GCM**, KDF is HKDF-SHA256 | One AEAD across the suite. ChaCha20-Poly1305 was considered for two reasons and rejected on both: the published X-Wing vectors pair it with ChaCha20 (`0x647a / 0x0001 / 0x0003`), but the halves of our triple are each pinned by a document anyway (X-Wing seed-to-key from draft-ietf-hpke-pq; HKDF-SHA256 + AES-256-GCM key schedule from RFC 9180 with X25519), so nothing is left unpinned; and software AES-GCM is slow without AES instructions, but the only ARM product is kydns, whose capsule is kilobytes. Consistency wins once neither argument has weight. |
| The recovery seed is split, not the private key's expanded form | Every `crypto/hpke` KEM reconstructs its private key from a 32-byte seed via `KEM.NewPrivateKey`. Splitting 32 bytes makes the shares the same size as today's, whatever the KEM. |
| Key ID is lowercase hex SHA-256 of the public key bytes | Cheap, deterministic, and long enough that a display match is a real match. |
| `Open` compares key IDs before decapsulating | The wrong-kit failure becomes cheap and named, instead of an AEAD failure after 1120 bytes of decapsulation. |

---

## Part 1 — The `recoverykey` package

New, standard-library only. It owns the keypair and the two operations that touch its seed.

```go
package recoverykey

// PrivateKey is the suite's recovery private key. It exists in memory during the
// ceremony that splits it and during a restore that combines it, and nowhere else.
type PrivateKey struct { /* seed [32]byte; key hpke.PrivateKey */ }

// PublicKey is what every product holds and seals to.
type PublicKey struct { /* key hpke.PublicKey */ }

const SeedBytes = 32
const PublicKeyBytes = 1216 // ML-KEM-768 encapsulation key (1184) + X25519 point (32)

var (
	ErrSeedLength      = errors.New("recoverykey: seed must be exactly 32 bytes")
	ErrPublicKeyLength = errors.New("recoverykey: public key must be exactly 1216 bytes")
)

func Generate() (PrivateKey, error)
func FromSeed(seed []byte) (PrivateKey, error)
func ParsePublicKey(b []byte) (PublicKey, error)

func (k PrivateKey) Seed() []byte      // the 32 bytes that are split; never anything else
func (k PrivateKey) Public() PublicKey
func (p PublicKey) Bytes() []byte      // 1216 bytes, what keyfile.Store persists
func (p PublicKey) ID() string         // hex SHA-256 of Bytes()

func Split(k PrivateKey, threshold, total int) ([]shamir.Share, error)
func Combine(shares []shamir.Share) (PrivateKey, error)
```

`Generate` is `hpke.MLKEM768X25519().GenerateKey()` followed by `Bytes()` to recover the
seed; `FromSeed` is `NewPrivateKey(seed)`. Both keep the seed alongside the HPKE key
because `hpke.PrivateKey.Bytes()` on a hybrid key returns the seed only when the key was
built from one, and this package must never be in a position where it cannot split what it
holds.

`Split` and `Combine` are thin over `shamir.Split(k.Seed(), …)` and
`FromSeed(shamir.Combine(shares))`. They exist so that the thing being split is the seed by
construction. Splitting the wrong 32 bytes fails loud at restore through the key ID check,
but "loud at restore" is the failure this design exists to move earlier.

`Combine` surfaces a wrong share set in one of two places: `shamir.Combine` refuses
mismatched sets, lengths and thresholds as it does today; anything that slips through and
is not 32 bytes fails `FromSeed` with `ErrSeedLength`. A wrong-but-32-byte reconstruction
yields a different keypair and is caught by `capsule.Open`'s key ID compare.

### Who calls what

| Call | Host | When |
|---|---|---|
| `Generate`, `Split`, `Public().ID()`, `Public().Bytes()` | kyrecovery | Once, in the ceremony. Seed zeroed after `Split`. Never persisted. |
| `ParsePublicKey`, `keyfile.Store` | each product | At pairing, receiving the public key over the authenticated channel. |
| `ParsePublicKey` from `keyfile.Load` | each product | Every backup, to call `capsule.Seal`. |
| `Combine`, `FromSeed` | the recovering product | At restore, after k shares arrive. Dropped when `Open` returns. |

The ceremony is the one recorded exception to "kyrecovery never holds the key". It holds
the seed for the duration of `Generate` and `Split`, in memory, and the ceremony code must
zero it and must not log it, persist it, or return it to any caller. That requirement is
Plan 5's to enforce and test; this document states it so Plan 5 cannot miss it.

---

## Part 2 — `capsule` becomes `kycap/3`

### Signatures

```go
func Seal(serviceName, appVersion string, files []File, deps, recipe map[string]any,
	threshold, totalShares int, to recoverykey.PublicKey) (raw []byte, m Manifest, err error)

func Open(raw []byte, with recoverykey.PrivateKey, targetDir string) (Manifest, []File, error)
```

`Seal` no longer returns a key. `Open` no longer takes bytes. The data key exists only
inside `crypto/hpke` for the duration of each call.

`ErrWrongRecoveryKey` is added to the package sentinels: the manifest names a recovery key
other than the one `Open` was given.

### Manifest

Two fields join `UnverifiedManifest`, both marshalled into the plaintext manifest and so
both inside the AAD like every other field:

```go
RecoveryKeyID   string `json:"recovery_key_id"`   // recoverykey.PublicKey.ID()
EncapsulatedKey string `json:"encapsulated_key"`  // base64 of the 1120-byte HPKE enc
```

Neither is secret. The encapsulated key is HPKE's `enc`, public by construction. The key
ID is a hash of a public key. Publishing both in the clear is what lets kyrecovery display
and pin the key ID without the private key, which is the whole point of the blind store.

`Threshold` and `TotalShares` stay. They now describe the split of the recovery seed rather
than of a per-capsule key, and they remain sealer-attested display metadata for kyrecovery's
custodian view. `Seal` keeps its existing topology check on them.

### Container

```go
const KycapFileFormat = "kycap/3"
```

`kycapFile` is unchanged in shape: `format`, `manifest` as raw bytes, `ciphertext` as
base64. The `ciphertext` no longer carries a nonce prefix — HPKE derives the nonce from the
key schedule and the sequence number, and a single-record container is sequence zero.

`kycap/2` joins the README's retirement table, unread. Its column reads: authenticated the
manifest, returned a raw key the caller had to protect and split per capsule.

### The HPKE call, exactly

Suite: `hpke.MLKEM768X25519()`, `hpke.HKDFSHA256()`, `hpke.AES256GCM()`.

`info` is the literal bytes of `KycapFileFormat`, `"kycap/3"`. It binds the container
format into the key schedule so a ciphertext lifted into some future container fails
without a format check having to remember to exist.

`aad` is the manifest's exact bytes, as today.

Seal:

```go
enc, sender, err := hpke.NewSender(to.key, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(KycapFileFormat))
// EncapsulatedKey = base64(enc); marshal manifest; then
ct, err := sender.Seal(manifestBytes, payload)
```

The manifest is marshalled *after* `NewSender` because it must contain `enc`, and it is the
AAD for the seal that follows. There is exactly one marshal, and its bytes are both the AAD
and what lands in the container, as today.

Open:

```go
if m.RecoveryKeyID != with.Public().ID() { return ErrWrongRecoveryKey }
enc, err := base64.StdEncoding.DecodeString(m.EncapsulatedKey)   // length-checked: 1120
recipient, err := hpke.NewRecipient(enc, with.key, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(KycapFileFormat))
payload, err := recipient.Open(cf.Manifest, ct)
```

then `verifyPayloadHash` and `extractPayload`, unchanged. The payload hash stays: it is
still the line that catches a container whose AEAD passed for a reason nobody predicted.

The single-shot `hpke.Seal`/`hpke.Open` helpers are not used. They take no AAD, and the
manifest-as-AAD is the property that retired kycap/1.

### What did not change

`parseContainer`, its bounds, `ReadUnverifiedManifest`, `buildPayload`, `extractPayload`,
the reserved file list inside the payload, `FileEntry`, the two-type manifest split. The
file list stays inside the encrypted payload for the reasons on `UnverifiedManifest.Files`.

---

## Part 3 — `keyfile.Store`

```go
// Store writes a caller-supplied key with the durability and permissions of LoadOrCreate,
// and refuses to replace a file that already exists.
func Store(path string, key []byte, enc Encoding) error
```

Products must persist a public key they were handed, not one they minted. `create` is the
only writer today and it generates random bytes. The change is a refactor: `create` becomes
`randRead` into a buffer followed by the write path, and `Store` is that write path with the
caller's bytes. One temp-file, fsync, `os.Link`, directory-sync sequence, two entry points.

The refusal to overwrite is not a convenience. Replacing the public key file is the
substitution attack — every later backup is sealed to an attacker's key — and `os.Link`'s
failure on an existing name is what makes that attack fail rather than succeed silently.
Rotation, when it comes, gets a deliberate path, not an overwrite.

---

## Part 4 — Data flow

**Once, on kyrecovery.** `Generate`. `Split` k-of-n. Render each share with
`shamir.Share.String()` onto a custodian card. Show `Public().ID()` so it can be written on
the cards. Persist `Public().Bytes()` as the suite public key and pin its ID. Zero the seed.

**At pairing, per product.** Kyrecovery hands the public key bytes over the authenticated
channel. The product runs `ParsePublicKey` — which fails on any length but 1216 — then
`keyfile.Store` in raw encoding. Kyrecovery records that this product was given this ID.

**Every backup, per product.** `keyfile.Load` the 1216 bytes, `ParsePublicKey`, `Seal`.
Deposit the container with kyrecovery. No secret is read, written or held.

**At kyrecovery, per deposit.** `ReadUnverifiedManifest`. Display. Refuse if
`RecoveryKeyID` is not the pinned ID. Record the container's digest and time in the audit
chain. Nothing else on the manifest is decided on.

**At restore, on a fresh product instance.** k shares arrive (Plan 5). `Combine`. `Open`
with the result: key ID compare, decapsulate, decrypt, payload hash, extract under the
existing containment. Drop the private key.

### Streaming

The streaming design (`2026-09-02-capsule-streaming-design.md`) keeps a plaintext manifest
at the head of the stream, so `recovery_key_id` and `encapsulated_key` ride there unchanged.
Its writer becomes one `hpke.Sender` sealing each record in sequence; its reader one
`hpke.Recipient` opening them in the same order. HPKE's sequence counter is what refuses a
reordered or dropped record, so the proposed `baseNonce` header field is deleted. The
trailer record and the truncation defence are unchanged. Plan 2 inherits exactly this and
re-decides nothing else.

---

## Part 5 — Errors

| Condition | Where it fails | Error |
|---|---|---|
| Wrong private key | `Open`, before decapsulation | `ErrWrongRecoveryKey` |
| `recovery_key_id` edited to match the wrong key | `Open`, at the AEAD | decrypt failure (AAD) |
| `encapsulated_key` edited, any length | `Open`, at length check or AEAD | `ErrCorruptCapsule` or decrypt failure |
| Public key bytes of wrong length | `ParsePublicKey` | `ErrPublicKeyLength` |
| Seed of wrong length | `FromSeed` | `ErrSeedLength` |
| Wrong share set | `shamir.Combine` (set, length, threshold) or `FromSeed` | shamir's sentinels or `ErrSeedLength` |
| Public key file already exists | `keyfile.Store` | `os.Link` error, `errors.Is(err, fs.ErrExist)` |
| Container format is `kycap/2` | `parseContainer` | `ErrUnknownContainer` |

---

## Part 6 — Testing

Every claim below is a property of the *proposed* code and is untested until the plan
lands. The repo's rule is that golden vectors come from a published document, never from
the implementation.

**Golden vectors, pinned in this repository's tests independently of Go's own, so a Go
release that changes a derivation fails here before it fails a product.** No published
vector covers our exact triple (`0x647a / 0x0001 / 0x0002`); two documents cover its two
halves, and both are used.

1. From draft-ietf-hpke-pq (Go's `hpke-pq.json`, KEM `0x647a`):
   `FromSeed(skRm).Public().Bytes() == pkRm` — 32 bytes in, 1216 out.
2. Same vector: `FromSeed(skRm).Public().ID()` equals the hex SHA-256 of `pkRm`, computed in
   the test from the vector's bytes rather than from the implementation.
3. From RFC 9180 (Go's `rfc9180.json`, suite `0x0020 / 0x0001 / 0x0002`, X25519 with
   HKDF-SHA256 and AES-256-GCM): `hpke.NewRecipient(enc, skRm, HKDFSHA256, AES256GCM, info)`
   followed by `Open(aad, ct)` reproduces `pt` for the first encryption. This pins the key
   schedule and AEAD path `capsule.Open` will use; test 1 pins the KEM it will use.

**Behavioural, one claim each:**

4. Round trip: `Seal` to a public key, `Open` with the matching private key; files and
   manifest match, and `Manifest.RecoveryKeyID == with.Public().ID()`.
5. `Open` with a second keypair returns `ErrWrongRecoveryKey`, and does so without reaching
   decapsulation — asserted by a container whose `encapsulated_key` is deliberately
   garbage, which would fail differently if decapsulation ran first.
6. Rewriting `recovery_key_id` in the plaintext manifest to the *wrong* key's real ID, then
   opening with that wrong key, fails at the AEAD, not the compare. This is the test that
   the field is inside the AAD and not merely present.
7. Rewriting `encapsulated_key` to another valid 1120-byte `enc` fails at the AEAD.
8. `TestUnverifiedManifestIsRewritableWithoutTheKey`'s pattern, extended: the keyless
   reader believes a rewritten `recovery_key_id`; `Open` does not.
9. `Combine` over indices `{1, 3, 5}` of a 3-of-5 split reproduces the original key ID.
   Consecutive indices are forbidden in this test — they make every Lagrange coefficient
   1 and pass in any field, which is how the 0x11d/0x11b split hid.
10. `FromSeed` refuses 31 and 33 bytes; `ParsePublicKey` refuses 1215 and 1217.
11. `keyfile.Store` writes owner-only, the file is fsynced, and a second `Store` to the
    same path fails with `fs.ErrExist` and leaves the first key's bytes intact.
12. `TestModuleDependenciesAreAllowlisted` and `TestOnlyPasswordImportsADependency` pass
    with no changes. Everything here is standard library.
13. A `kycap/2` container from the existing fixtures fails `Open` with
    `ErrUnknownContainer`, not a decrypt error and not a panic.

**Fuzz.** The existing container fuzz target is unchanged; the manifest parser gained two
string fields and nothing else.

---

## Part 7 — Migration

Breaking. Tagged **v0.4.0**. `kycap/2` is retired unread; nothing is in the wild.

gridlock-server is the only current capsule consumer. It is re-forked against the
migrated scaffold in Plan 3, and its move to `Seal(…, to)` / `Open(raw, with, …)` lands
there rather than as a Phase-2-style pin bump. Until Plan 3 lands, gridlock's
`ky-primitives-compat.yml` is red. That is the expected, visible state, and a statement
that gridlock is compatible is unproven until it is green again.

kybookmarks-server and kypassword-server import only `auditchain` and are unaffected.

The README's `## capsule` section is rewritten around the new signatures, `kycap/2` is
added to the retirement table, and `## recoverykey` is added between `## capsule` and
`## shamir`.

---

## Claims register

**M** was measured by running something. **P** is proposed and has never been executed.

| # | Claim | | Evidence, or what must test it |
|---|---|---|---|
| 1 | `crypto/hpke` is public API in Go 1.26 | M | `grep 'pkg crypto/hpke' /usr/lib/go/api/go1.26.txt` matches; no other api file does |
| 2 | X-Wing is `hpke.MLKEM768X25519`, id `0x647a`, from draft-ietf-hpke-pq | M | `crypto/hpke/pq.go:20-43` |
| 3 | Every `crypto/hpke` KEM rebuilds its private key from a 32-byte seed | M | `hybridKEM.NewPrivateKey` refuses `len != 32` (`pq.go:254`); `dhKEM.NewPrivateKey` takes the curve's 32-byte key |
| 4 | Hybrid `PrivateKey.Bytes()` returns the seed only if built from one | M | `pq.go:318-323`: returns error when `seed == nil` |
| 5 | Published X-Wing vectors exist with `skRm` 32 B, `pkRm` 1216 B, `enc` 1120 B | M | `hpke-pq.json`, two vectors for `0x647a`; one with HKDF-SHA256 + ChaCha20-Poly1305, one with SHAKE256 |
| 6 | No published X-Wing vector uses AES-256-GCM; RFC 9180 covers HKDF-SHA256 + AES-256-GCM with X25519 | M | `hpke-pq.json` has `aead_id 0x0003` for both `0x647a` vectors; `rfc9180.json` has `0x0020/0x0001/0x0002` |
| 7 | `hpke.Sender.Seal` takes an AAD and sequences nonces; single-shot `hpke.Seal` takes none | M | `hpke.go:171-195` |
| 8 | Sealing to the public key leaves no data key reachable by the caller | P | Test 4 plus a code review that no exported symbol returns or accepts one |
| 9 | Both new manifest fields are inside the AAD | P | Tests 6 and 7 |
| 10 | Wrong-key failure precedes decapsulation | P | Test 5 |
| 11 | A non-consecutive share set reproduces the key | P | Test 9 |
| 12 | `keyfile.Store` never replaces an existing key | P | Test 11 |
| 13 | The implementation matches the draft's vectors | P | Tests 1–3 |

## Follow-ups this design does not do

- **Plan 2** picks up the `baseNonce` deletion and the sender/recipient contexts.
- **Plan 5** owns the ceremony's zeroing and no-persist requirement, the key ID pin, the
  share relay, and the deposit-time refusal.
- **Plan 3** moves gridlock to the new signatures.
- **Rotation** gets its own design when a reason to rotate exists.
