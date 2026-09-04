# kyrecovery as a blind store

Design, 2026-09-04. No implementation. This is Phase 5 of the suite migration
(`2026-09-02-suite-migration-design.md`), redone after the decisions of 2026-09-03: products
seal and restore their own capsules; kyrecovery stores ciphertext and never holds a key;
the suite has one long-lived recovery keypair (`2026-09-03-recovery-keypair-design.md`).
The Phase 5 text in the migration spec predates those decisions and is superseded here.

## What kyrecovery is today

Measured 2026-09-04 against `kyrecovery-server` main `744dd37`. Every claim below was read
off the code with a file:line, not remembered.

It is the opposite of a blind store. `POST /api/backup/push` (`internal/server/server.go:909`)
takes **plaintext files** from a paired product, mints an AES-256 master key, packs its own
tar container (`internal/capsule`), Shamir-splits the key, runs a decrypt-and-verify drill,
and **returns the shares to the product in the HTTP response** (`server.go:1063`). Its
"ceremony" (`internal/ceremony`) is a quorum-to-decrypt session, not a keypair ceremony.
The claim response (`server.go:894-902`) carries an API token and nothing about keys.
Nothing in the repo mentions a recovery key ID. There is no ky-primitives dependency, no CI,
`go 1.25.0`, a committed database and binary.

Decided against that state, 2026-09-04:

| Decision | Choice | Rejected |
|---|---|---|
| Share relay to a remote recovering instance (option C) | **Deferred** to its own plan. Restores use the product's `restore` command with shares typed from cards. | A custodian CLI; a browser relay. Both need custodian-side crypto before the blind store exists. |
| Where the keypair ceremony runs | **In the browser**, as a WASM build of `recoverykey` served by kyrecovery. Spike: 3.6 MB module; `Generate` + `Split` produce a valid key ID, a 1216-byte public key and printable shares under Node. | A CLI on a throwaway host (operator burden, a machine to destroy); both (two paths). |
| How much to delete | **Everything that needs a key.** | Keeping UI shells; a flag for the old paths. |

## Non-goals

- The share relay. This document fixes the deposit, the pin, the pairing hand-off and the
  ceremony. A recovering instance gets its k shares from custodians directly.
- Key rotation. `keyfile.Store` on the product side and the single-row import here both
  refuse a second key on purpose. Rotation gets a deliberate path in a later document.
- Streaming deposits. A capsule is bounded by the library's container cap. Products with
  data beyond it need the streaming container (`2026-09-02-capsule-streaming-design.md`)
  first; kyrecovery stores whatever bytes arrive under the cap.
- Reading the retired tar container. Nothing is in the wild.

---

## Part 1 — What kyrecovery becomes

A store of sealed bytes it cannot read, with a public key it hands out and a hash chain
over what it received.

**Holds:** kycap/3 containers; each container's `UnverifiedManifest` fields; the SHA-256 of
each container as deposited; an audit chain over deposits, verifications, pairings and the
key import; custodian names; the suite recovery public key and its ID; paired-app API
tokens; the server keyring for its own secrets.

**Never holds:** a recovery private key or seed, a Shamir share, a plaintext payload, a
per-capsule data key. There is no code path that decrypts a capsule.

**Adopts from ky-primitives (v0.4.x):** `recoverykey` (parse and pin the public key; the
WASM ceremony), `capsule` (`ReadUnverifiedManifest`, the container cap constants),
`auditchain` (the ledger), `password` (admin login), `keyfile` (the keyring master key).
`shamir` arrives through `recoverykey` and is used only inside the WASM module.

**Also:** `go 1.26.6` (the library's floor), a CI workflow with the same shape as the
other repos (build, vet, gofmt, race tests, govulncheck, a `ky-primitives-compat` job), and
the committed `data/kyrecovery.db` and binary removed from the tree.

## Part 2 — Ceremony

An admin-only page at `/admin/ceremony` loads `ceremony.wasm`, a `GOOS=js GOARCH=wasm` build
of a small `cmd/ceremony-wasm` that exposes one function: given k and n, call
`recoverykey.Generate`, `recoverykey.Split(k, n)`, and return the public key bytes, the key
ID, and the n share strings. The page renders n cards — share string, key ID, k-of-n,
date, a blank line for the custodian's name — for printing, and posts **only**
`{public_key: base64(1216 bytes), threshold, total_shares}` to `POST /api/recovery-key`.

The server: `recoverykey.ParsePublicKey` (fails on any length but 1216), computes the ID,
inserts the single row of `recovery_key(id, public_key, key_id, threshold, total_shares,
imported_by, imported_at)`, refuses with 409 if a row exists, appends an audit event
`recovery_key_imported` carrying the key ID and topology. Shares never reach the server;
the request body has no field for them and the handler decodes a struct with none.

The page states the constraints the keypair spec puts on the ceremony host, restated for a
tab: open in a fresh private window; no browser extensions; on a machine that will not
hibernate during the ceremony; close the tab after the cards are printed and the import is
confirmed. The seed exists in the tab's memory from `Generate` until the tab closes and
cannot be erased before that; a tab is a weaker ephemeral host than a destroyed VM and a far
stronger one than the server process. This is the trade taken.

The WASM module is built in CI from the same commit as the server and embedded, so the code
that generates the suite's root key is the code in this repository, served over the admin
session, not fetched from anywhere else.

## Part 3 — Pairing

Unchanged except the claim response and one refusal.

`POST /api/pairing/claim` returns, in addition to today's fields:

```json
{"recovery_public_key": "<standard base64, 1216 bytes>", "threshold": 3, "total_shares": 5}
```

If no recovery key has been imported the claim is refused with 409 and a message saying the
ceremony has not run; the pairing code is not consumed. `paired_apps` gains
`recovery_key_id TEXT` recording the ID handed to that product. `pkg/client.ClaimResponse`
gains the three fields. The product side (`backup.StoreRecoveryKey` in the scaffold) already
consumes exactly this shape and refuses a claim without it.

## Part 4 — Deposit

`POST /api/backup/deposit`, bearer token of a paired app, `Content-Type:
application/octet-stream`, body is the sealed container. Steps, each a refusal by name:

1. Body capped at the library's container bound (`384 MiB`, the same constant `Open`
   enforces; import it once it is exported alongside the size limits) → 413.
2. `capsule.ReadUnverifiedManifest(body)` → 400 on any parse error.
3. `manifest.RecoveryKeyID != pinned` → 409 `wrong recovery key`, naming both IDs (both
   public). Nothing is written.
4. `manifest.ServiceName != pairedApp.ServiceName` → 403.
5. SHA-256 the body. Write to `<DataDir>/capsules/<capsuleID>.kycap` through the existing
   temp-file, fsync, rename path. Refuse a duplicate capsule ID (409); a product that
   re-sends the same bytes gets the original record back if the digest matches.
6. Insert `capsules(capsule_id, service_name, app_name, app_version, created_at,
   payload_hash, threshold, total_shares, recovery_key_id, encapsulated_key, size_bytes,
   digest, deposited_at, paired_app_id)` — every value from the unverified manifest except
   the size, digest and time, which are kyrecovery's own.
7. Append audit event `capsule_deposited` with capsule ID, service, digest, size.
8. Kick off S3 replication of the blob, unchanged.
9. Respond `{capsule_id, digest, size_bytes, deposited_at}`.

Rate limits and concurrency slots stay as they are for the push endpoint today. The push
endpoint, its payload type and `pkg/client.PushBackup` are deleted.

The manifest is displayed, never decided on. The one decision the server takes from it is
step 3, and that field is a hash of a public key it already holds.

## Part 5 — Integrity attestation

`GET /api/capsules/{id}/verify` re-reads the blob, compares its SHA-256 with `digest`,
appends `capsule_verified` (or `capsule_corrupt`, which also flags the row) and returns
the result. A daily job does the same for every capsule and for the S3 copy where one
exists. `GET /api/capsules/{id}/download` returns the bytes with `X-Capsule-Digest`.

The audit ledger moves to `auditchain`: the chain key is derived from the keyring as today,
records are length-prefixed fields, the anchor (count and last hash) is kept outside the
log, and `VerifyStream` replaces the paged `VerifyChain`, which removes the 100000-record
bug the migration spec recorded. Existing events are not carried: nothing is in the wild.

The diff and timeline inspector (`internal/diff`) is rewritten to read `capsules` rows
rather than manifests from containers; its inputs are the same fields.

## Part 6 — Deletion

Removed outright: `internal/capsule`, `internal/adapter`, `internal/drill`,
`internal/ceremony` (the decrypt quorum), `internal/crypto/shamir.go` and
`envelope.go`, `internal/export` (the recovery kit that carried shares), the capture
handler and its UI, the auto-drill, the shares dialog, the TUI's restore path, and the CLI
subcommands `capture`, `restore`, `drill`, `split-key`, `combine-shares`, `export-kit`.
`pkg/client` keeps `ClaimPairing` and gains `Deposit(ctx, serverURL, token, container
[]byte)`.

Kept: pairing, custodian records (name, email, fingerprint — used to label cards and
nothing else), the S3 replication target machinery, the admin UI for capsules and audit,
the keyring, SSO.

## Part 7 — Restore, for the record

A fresh product instance restores from a capsule and k shares: the operator downloads the
`.kycap` from kyrecovery (admin session) or from wherever the product's own export put it,
runs the product's `restore` command, and types the custodians' shares from their cards.
`capsule.Open` proves the bytes are the sealed ones and were sealed to the pinned key; the
operator compares `CapsuleID` and `CreatedAt` against kyrecovery's deposit record, which is
where freshness comes from. kyrecovery is not involved in the restore beyond the download.

## Part 8 — Errors

| Condition | Where caught | Response |
|---|---|---|
| Claim before a key is imported | `handlePairingClaim` | 409, code not consumed |
| Second key import | `handleRecoveryKeyImport` | 409 naming the existing ID |
| Public key not 1216 bytes | `recoverykey.ParsePublicKey` | 400 |
| Deposit over the container cap | body limiter | 413 |
| Deposit not a kycap/3 container | `ReadUnverifiedManifest` | 400 |
| Deposit sealed to another key | key-ID compare | 409, both IDs |
| Deposit for another service | service compare | 403 |
| Stored blob digest mismatch | verify | 200 with `corrupt: true`, row flagged, audit event |

## Part 9 — Tests

1. Deposit refuses each of: oversized body, malformed container, wrong key ID, wrong
   service, duplicate ID with a different digest. Each refusal is by the named status.
2. Deposit accepts a container sealed by the library's `Seal` to the imported public key
   and records digest, size and the manifest fields verbatim.
3. Claim refuses without a key; with a key returns the exact public key bytes and topology
   and records the key ID on the paired app.
4. Import is single-shot; a second import is refused and the first row is unchanged.
5. Round trip, in-process: generate a keypair in the test, import its public half, seal
   with `capsule.Seal`, deposit, download, `capsule.Open` with the test's private key.
   The private key exists only in the test.
6. Verify detects one flipped byte in the stored blob and flags the row.
7. `ceremony.wasm` is built in CI and run under Node with k=3, n=5: the output has a
   64-hex key ID, a 1216-byte public key, five share strings that `shamir.ParseShare`
   accepts, and any three of which `recoverykey.Combine` turns into the key whose public
   half matches. This is the one place the private key is combined outside a product, and
   it is a test.
8. The audit chain verifies with `auditchain.VerifyStream` after a deposit, a verify and a
   key import; deleting the last record fails verification against the anchor.
9. Nothing in the binary decrypts: `grep` for `hpke.NewRecipient`, `recoverykey.Combine`,
   `recoverykey.FromSeed` and `capsule.Open` outside `_test.go` and the WASM command is
   empty, asserted by a test.

## Claims register

| Claim | Status |
|---|---|
| `recoverykey` compiles to `js/wasm` and `Generate`/`Split` run there | **Measured** 2026-09-04 (spike under Node, 3.6 MB module). |
| The seed cannot be erased from a Go process or a WASM tab before exit | Stated; follows from the keypair spec's measured claim about Go. |
| A tab in a private window on a non-hibernating machine is an acceptable ephemeral host | **Decision**, 2026-09-04, not a measurement. |
| The container cap constant equals what `Open` enforces | Measured in the library (`capsule/container.go`); kyrecovery must import, not mirror. |
| Nothing in kyrecovery decrypts after Part 6 | Unproven until test 9 exists. |
| The scaffold's `StoreRecoveryKey` consumes the Part 3 response as written | Measured against ky_server_base master `9ee016a`. |
