# ky-primitives

Shared security primitives for the Busness.app suite.

The dependency budget is **`golang.org/x/crypto` and the `golang.org/x/sys` it drags in,
and nothing else.** Everything but `password` is standard-library-only. The rule was "no
dependencies, ever" so that products with minimal trees could import this for free —
`kypassword-server`'s `go.mod` requires nothing at all — and Argon2 is the one thing that
broke it: the suite standardised on it for password hashing, and it is neither in the
standard library nor on a proposal track.

Two tests hold that line. `TestModuleDependenciesAreAllowlisted` fails on any `require`
outside the budget; `TestOnlyPasswordImportsADependency` discovers every other package and
fails if any of them imports one. A consumer that only wants `capsule` compiles none of
`x/crypto`, but it does inherit the requirement in its own `go.mod` — that is the cost.

`go list -m all` names five `golang.org/x` modules because they sit in `x/crypto`'s own
requirement graph. Only two reach `go.sum`, and the build compiles three packages:
`x/sys/cpu`, `x/crypto/blake2b` and `x/crypto/argon2`.

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
| `kycap/2` | this package | `kycap/1` with the manifest bound in as AAD |
| tar | `kyrecovery-server` | tar of `manifest.json`, `nonce.bin`, `payload.enc`, AAD-bound |

`Open` reads all three and always will — dropping any orphans backups already on disk.
`Seal` writes `kycap/2` only, so the suite stops accumulating formats.

`kycap/1` authenticates its ciphertext and nothing else. Its `capsule_id`, `service_name`,
`threshold`, `total_shares` and verification recipe were all rewritable by someone who
never learned the key, so a 2-of-3 kit could be restated as 1-of-1 and still open. `kycap/2`
binds the manifest bytes into the AEAD. The manifest is carried and authenticated as the
exact bytes that were read, not a re-encoding of a decoded struct, so nothing depends on
two encoders agreeing forever.

**Readers migrate before writers.** A product still on the old reader cannot open a
`kycap/2` capsule.

`Seal` refuses a kit that cannot exist — `threshold` below 2, above `totalShares`, or a
total past 255 — because a manifest that records recovery topology without checking it
sends a custodian looking for shares that were never issued.

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

Extraction runs through an `os.Root` handle, so every component resolves against a
directory descriptor and no member can name a location outside the target. Containment
used to be a string comparison plus `Lstat` on each parent, which a process able to swap a
checked parent for a symlink could step through — `O_NOFOLLOW` only guards the last
component. Go picks `openat2` where the kernel has it, so this carries no minimum kernel of
its own. A failed extraction rolls back whatever it wrote, because the target must be empty
to start and a half-restored keyset otherwise poisons every retry.

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
card := shares[0].String()                // ky2-3-9f2a71c4...-1-a1b2...-7d1e
```

A share is self-describing: `ky2-<threshold>-<set id>-<index>-<value>-<check>`. The share
used to be `index-hex` and nothing else, which meant it could not defend against any of the
four ways a custodian gets this wrong. Each field is there for one of them.

| Field | Refuses |
|---|---|
| `ky2` | A share from the suite's 0x11d implementations, which was byte-indistinguishable and reconstructed a different secret with no error |
| threshold | Combining fewer shares than the split needs — previously a silent wrong answer |
| set id | Mixing shares from two different splits — also previously silent |
| check | A character mistyped off the card, before it becomes a wrong secret |

`Combine` still uses every share it is given; passing more than the threshold is correct.
Bind a hash of the plaintext alongside anyway — `capsule`'s payload hash is that check.

`ky1` cards still parse; they were printed and put in envelopes. Their 32-bit set id was
too narrow for its job — two splits collided with even odds after about 65,000 of them, and
a collision means the check silently does not happen — so `ky2` carries 128 bits and a ky1
id widens into the low four bytes. A ky1 share re-rendered prints as `ky2`, so render at
split time.

Every share must declare a threshold of 2..255. It used to be enforced only above zero,
which is what an absent field decodes to, so a `Share` filled in by a deserialiser landed
in the unchecked mode by default.

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

Persistence is a parameter of `Append`, not the caller's next statement. The chain's
in-memory head is a claim about what is on disk: advancing it first meant a failed insert
left the next record chained onto one that never existed, and a record stored without its
anchor left the opposite inconsistency, with no way to roll back either. `persist` runs
under the lock that reserves the sequence number, and the chain advances only if it
returns nil.

`Verify` requires the `Anchor` — a count and head hash kept outside the log. Hashes alone
cannot catch a log with records removed from the end, because what remains still chains
correctly, so the anchor is a parameter rather than an option.

`Resume` requires it too. A valid digest does not make a record the tail — every record in
a healthy chain carries one — so resuming from the middle was accepted and the next append
minted a sequence number that already existed. The anchor is the only thing that knows
where the end is. Sequence 0 and `MaxUint64` are refused: `Append` starts at one, and
minting `count+1` from the top wraps to zero.

`AppendContext` bounds the wait for the chain lock, not `persist`. `persist` still runs
under the lock — the record and its anchor have to be written together — so give it its own
timeout, and do not call back into the `Chain` from it: the lock is not reentrant, and the
anchor it would ask for is already one of its arguments.

```go
chain, err := auditchain.New(key)          // or Resume(key, lastRecord, anchor)
rec, err := chain.Append(func(r auditchain.Record, a auditchain.Anchor) error {
    return store.WriteRecordAndAnchor(r, a) // one transaction
}, "login", user)
err = auditchain.Verify(key, records, anchor)
err = auditchain.VerifyStream(key, rows, anchor) // same, for a log too large to hold
```

Chains in this suite reach six figures, and the bug that follows from paging them is
specific: `kyrecovery-server`'s `VerifyChain` read a fixed 100000 events and then reported a
sequence gap on a perfectly healthy chain. `VerifyStream` removes the reason to page. A
record yielded with a non-nil error fails the verification rather than ending the walk, so a
store that dies mid-read cannot look like a short chain.

`Anchor` is `{Count, Hash}`, which matches `kyrecovery-server`'s `ledger.head` but **not**
`kypassword-server`'s `audit.state`. That carries a third field — the first index required
to be keyed — because KyPassword has a two-version chain: v0 records predating the key,
verified under unkeyed SHA-256, and v1 under HMAC. Without that field an attacker downgrades
a keyed entry to v0 and recomputes its hash with the public algorithm. This package has no
version concept and cannot express it, so **KyPassword cannot migrate onto `auditchain`
without either abandoning its v0 records or adding versioning here.** That is an open
decision, not an oversight.

`Fields` are opaque and storage is not this package's business. The three implementations
logged different things and wrote to JSON lines, a file and a database; forcing one schema
on them is what made them diverge, and where the bytes went was never the part that broke.

## password

Hashes and verifies passwords with Argon2id.

The suite ran three algorithms and five parameter sets:

| Repos | Algorithm | Parameters |
|---|---|---|
| `ky_server_base`, `gridlock-server` | Argon2id | m=64 MiB, **t=1**, p=4 |
| `kysignon-server`, `kyrecovery-server` | Argon2id | m=64 MiB, t=3, p=4 |
| `kydns-server` | Argon2id | m=64 MiB, t=3, **p=2** |
| `kynotes-server`, `kypost-server` | scrypt | N=2^17 |
| `kybookmarks-server` | scrypt | **N=2^15** |

The Argon2 encodings are mutually parseable, so a hash minted at t=1 verified in a t=3
product at a third of the intended attacker cost and nothing flagged it. This package is
the one answer: RFC 9106's second recommended profile, **m=64 MiB, t=3, p=4**, self-describing
in PHC form. The first recommended profile asks for 2 GiB, which no login endpoint can
afford per request.

**A malformed stored hash is an error, never a fallback.** `ky_server_base` and
`gridlock-server` re-split the string when the parameter segment fails to parse and, if it
merely starts with `$argon2id$`, verify against their compiled defaults instead. `parse`
here requires all six PHC segments, the exact algorithm, version 19, and three readable
parameters.

**Parameters are bounded on the way in.** A stored hash is attacker-controlled wherever the
store is, and `m=4294967295` asks for 4 TiB and OOM-kills the process on the next login
rather than failing it. Accepted: 8–256 MiB, t 1–10, p 1–16, salt ≥8 bytes, hash ≥16.
`kypost-server` bounds its scrypt equivalent for exactly this reason; nothing on the Argon2
side did.

**Derivations are bounded and shed rather than queue.** Four concurrent slots at 64 MiB caps
derivation memory at 256 MiB. Past a 2-second wait `Hash` and `Verify` return `ErrBusy`, which
callers should answer 503 to and must **not** spend a lockout strike on — the server is saying
"not now", not the user getting the password wrong. `kynotes-server` bounds the same way but
blocks forever, so a burst parks unbounded goroutines and overload reports itself as a wrong
password.

Concurrent derivations are bounded in **two dimensions**: 256 MiB of memory and 16 Argon2
lanes, each reservation the size that hash actually asks for, both taken together under one
queue. A request needing more than either whole budget fails immediately rather than waiting
for what it can never get.

A slot count alone bounded how many derivations ran, not how large they were, and `Verify`
accepts a stored hash asking for anything up to 256 MiB — so four slots admitted 1 GiB while
the comment above them claimed 256 MiB. Memory alone was no better: a stored hash at the
8 MiB floor reserves a thirty-second of the byte budget, so 32 run at once, each free to ask
for 16 lanes — **512 lanes**, comfortably under the memory ceiling and quite enough to take
the login endpoint with it. `Verify` reads those parameters out of the stored hash, so
whoever can write the store chooses them. CPU was written off as degrading rather than
killing, which is true of one derivation and false of the fleet a byte budget admits.

Taking both under the same single acquirer is what keeps the second dimension free: two
waiters can never each hold part of what the other needs.

The PHC parser compares against the canonical spelling rather than scanning. `fmt.Sscanf`
reads the fields it is asked for and ignores the rest, so `p=4TRAILINGGARBAGE`, `p=04` and
`v=19GARBAGE` all verified clean.

```go
encoded, err := password.Hash(plaintext)        // "$argon2id$v=19$m=65536,t=3,p=4$..."
ok, err := password.Verify(plaintext, encoded)  // ErrMalformed, never a silent default
stale, err := password.NeedsRehash(encoded)     // upgrade on next successful login
```

`Verify` accepts a weaker-but-valid hash so a deployment rehashes on login instead of
locking everyone out. Pair it with `NeedsRehash`; no Argon2 repo in the suite had either.

## totp

RFC 6238 one-time passwords. Pinned to the published RFC 4226 Appendix D vectors, so the
construction is checked against a document rather than against itself.

All four implementations in the suite agreed on the arithmetic — HMAC-SHA1, 20-byte secret,
6 digits, 30-second period — so **enrolled secrets stay valid across a migration onto this
one**. They disagreed on everything around it, and two of those differences outlive the
request.

`ky_server_base` and `gridlock-server` build the enrolment URI by interpolation:

```go
fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&...", issuer, accountName, secret, issuer)
```

An account name carrying a `?` starts the query string early. Parsed:

```
account = "x?secret=ATTACKERAAAAAAAA&digits=8"
  enrolled secret -> ATTACKERAAAAAAAA        digits -> 8
```

The user's phone holds a secret the server never issued, until they re-enrol. Nothing
errors. `ProvisioningURI` escapes the label and builds the query with `url.Values`.

The same two return a bare `bool` from validation, so a caller cannot know which step
matched and cannot spend it — a phished code stays live for the full 90-second window.
`Validate` returns the counter:

```go
counter, ok := totp.Validate(secret, code, time.Now())  // record counter, refuse a repeat
uri := totp.ProvisioningURI(issuer, account, secret)
```

## recoverycode

One-time codes that bypass every other factor, so their strength is the account's strength.

`ky_server_base`, `gridlock-server` and `kysignon-server` issue 8 symbols over a 32-symbol
alphabet — **40 bits** — and store them as a bare SHA-256. That is searchable offline by
anyone who reads the store. This package issues 12 symbols: 60 bits.

Hashing and storage stay with the caller; the products disagree about the hash for reasons
this package cannot settle, and it is not what diverged dangerously. What is here is
generation, the normalisation both sides of a comparison must agree on, and `MatchCode`,
which normalises and hashes before scanning every entry instead of breaking on the first
hit — `ky_server_base`'s redeem loop
reports the matching code's position in the list through its timing. An empty stored entry
is a redeemed slot and never matches, so a caller blanks in place rather than removing and
renumbering, which is how two concurrent redemptions lose each other's write.

`Match` was a digest comparison named for codes. Both parameters were strings, so passing
what the user typed compiled, ran, and never matched: enrolment hashed `Normalize(code)`
and a redemption path that forgot the same call rejected a valid code during the emergency
the code exists for. It is now `MatchDigest`, and `MatchCode(code, digests, hash)`
normalises internally so the two sides cannot disagree.

## keyfile

Loads a long-lived secret from disk, creating it on first use. Seven products did this
seven ways:

| Product | On a corrupt key file | First-boot race | fsync |
|---|---|---|---|
| `kynotes-server` | **continues with an empty secret** | unguarded | no |
| `kypassword-server` | **regenerates, orphaning every old record** | unguarded | no |
| `kysignon-server` | refuses to start | unguarded | no |
| `kyrecovery-server` | refuses | `O_EXCL` | no |
| `kypost-server` | refuses | mutex + recheck | yes |

This package refuses rather than guesses: an existing file that does not decode to exactly
the expected size is an error and is left untouched. `O_EXCL` settles the cross-process
race, and the loser re-reads the winner's key rather than returning one that was never
persisted. The file and its directory are both fsynced, because a crash after first boot
otherwise leaves a zero-length file that the refusal above then reports forever.

`RequireOwnerOnly` is exported separately. Nothing in the suite checked that a key file is
still `0600`, so one relaxed by a stray chmod or a restore kept being used as though it
were secret.

```go
key, err := keyfile.LoadOrCreate(filepath.Join(dir, "audit.key"), 32)
```

## derive

The login secret a client sends in place of a password: PBKDF2-SHA256 stretched, then
HKDF-SHA256 expanded under a per-product label.

`kynotes-server` and `kypost-server` both do this, each mirroring a **browser-side
TypeScript implementation**. That makes it a contract across four programs rather than a
helper — change any byte and every user is locked out. The golden vectors in the test were
produced by running `kynotes-server`'s implementation, not this one, and they pass, so that
product can adopt this package without a single login breaking.

Both existing copies import `golang.org/x/crypto/pbkdf2` and `.../hkdf`. Both moved into
the standard library in Go 1.24, so **adopting this package deletes a dependency from each
rather than adding one** — which is the only reason it can live here at all.

```go
secret, err := derive.AuthSecret(password, saltB64, iterations, "kynotes/auth/v1")
salt, err := derive.SyntheticSalt(pairingKey, "login-salt/v1", username)
```

Iterations are bounded to 100,000–12,000,000, the range both products already agreed on: the
value arrives from a client or a stored record, and unbounded it buys minutes of CPU per
login.

A ceiling is not admission control, though — it bounds one call and says nothing about how
many run at once, so a modest burst at the ceiling takes every core and starves the handlers
that would have shed it. **Four concurrent slots and a 2-second wait**, past which
`AuthSecret` returns `ErrBusy` — 503, and no lockout strike. PBKDF2 is single-threaded, so a
slot really is a core. The budget is `derive`'s own rather than `password`'s because this
package is standard-library-only by design and importing `password` would pull `x/crypto`
into it. `SyntheticSalt` lower-cases the username, because keying anything off the raw string
lets one account present as many and quietly multiplies any per-account budget above it.
