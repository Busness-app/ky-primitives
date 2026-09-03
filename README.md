# ky-primitives

Shared security primitives for the Busness.app suite.

The dependency budget is **`golang.org/x/crypto` and the `golang.org/x/sys` it drags in,
and nothing else.** Everything but `password` is standard-library-only. The rule was "no
dependencies, ever" so that products with minimal trees could import this for free —
`kypassword-server`'s `go.mod` named no third-party module at all, and now names exactly
one: this library — and Argon2 is the one thing that broke it: the suite standardised on it for password hashing, and it is neither in the
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

One container holds real recovery data on disk today:

`kycap/2`: a JSON object holding the manifest, a base64 ciphertext with the
nonce prefixed, and nothing else. The manifest is bound into the AEAD, so every field
describing the capsule is authenticated rather than merely present. It is carried and
authenticated as the exact bytes that were read, not a re-encoding of a decoded struct, so
nothing depends on two encoders agreeing forever.

Two containers came before it and both are retired:

| Container | Was written by | Why it is gone |
|---|---|---|
| `kycap/1` | `kysignon-server` | Authenticated its ciphertext and nothing else |
| tar | `kyrecovery-server` | Authenticated its ciphertext and its own `aad` string, not the rest of the manifest |

In both, `capsule_id`, `service_name`, `threshold`, `total_shares` and the verification
recipe were rewritable by anyone who could reach the file, without the key — a 2-of-3 kit
could be restated as 1-of-1 and still open. Neither server needs its old capsules read, so
the readers were retired rather than kept: a reader that half-trusts a manifest cannot tell
its caller which half.

`Seal` refuses a kit that cannot exist — `threshold` below 2, above `totalShares`, or a
total past 255 — because a manifest that records recovery topology without checking it
sends a custodian looking for shares that were never issued.

```go
m, files, err := capsule.Open(raw, key, "/var/restore")
raw, key, m, err := capsule.Seal(name, version, files, nil, nil, 2, 3)
```

`Open` returns the manifest because a successful `Open` is the only proof it was not
rewritten. `Seal` returns one too: `capsule_id`, `created_at` and `payload_hash` are minted
inside `Seal` and have no other source, and without them on the return a caller had to
re-parse its own output through `ReadUnverifiedManifest` to read fields it had just
authored. `gridlock-server` did exactly that. `ReadUnverifiedManifest` reads a manifest
without a key and returns a different type, `UnverifiedManifest`, so the compiler stops it
reaching anything that decides on it — a threshold read without the key is a threshold
anyone who can reach the file chose.

```go
m, files, err := capsule.Open(raw, key, "/var/restore")   // authenticated
m, files, err := capsule.Open(raw, key, "")               // decode only, writes nothing
raw, key, m, err := capsule.Seal(name, ver, files, nil, nil, 2, 3) // the sealed manifest
u, err := capsule.ReadUnverifiedManifest(raw)             // no key; show, do not decide
```

`errors.Is` a failed `Open` against `ErrCorruptCapsule` to tell a malformed container from
a bad key.

The ciphertext field is standard base64 in and out. Decoding used to also accept raw-url,
for capsules `ky_server_base` and `gridlock-server` encoded that way and never persisted;
with one writer left, a second accepted spelling is only a second thing that has to stay
true.

`key` is raw bytes, never a hex string. The suite's implementations disagreed on that.
Here the mistake is loud: `container.go` requires exactly 32 bytes, so the hex spelling of
a 32-byte key is 64 bytes and is refused outright. It was silent in the implementations
this replaced, which hashed or truncated whatever they were handed into 32 bytes and went
on to decrypt garbage.

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
hardlinks, directories, device nodes, FIFOs, two members that normalise to one
destination, archives over 256 MiB expanded, members over 64 MiB, more than 4096 files,
and any restore into a non-empty directory. File modes are clamped to owner-only — a
restored capsule carries signing keys, and an archive header is attacker-controlled.

The two size numbers are memory budgets rather than archive sizes, because `Open` holds
the raw container, the decrypted payload and every expanded member at once. They are the
values `capsule/extract.go` enforces; raising them is what a streaming `Open` is for.

Every refusal in that list is covered by a test in `capsule/hardening_test.go` or
`capsule/review_test.go`, with one exception: the 256 MiB expansion budget and the 64 MiB
member ceiling are exercised on the `Seal` side only, and `capsule/limits_test.go` asserts
the constants rather than the refusal. An extraction-side test for both is outstanding.

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

The set id is 128 bits. The first version of this format carried 32, which reached even
odds of a collision after about 65,000 splits — a number a deployment issuing recovery kits
reaches — and a collision means the check the field exists for silently does not happen.
The narrow format is not parsed: nothing outside this package ever wrote a share, so there
are no cards to strand, and a narrow id accepted "for compatibility" is the same collision
still reachable.

Every share must declare a threshold of 2..255. It used to be enforced only above zero,
which is what an absent field decodes to, so a `Share` filled in by a deserialiser landed
in the unchecked mode by default.

## auditchain

Builds and verifies a tamper-evident hash chain over audit records.

Three implementations existed, with three tuple layouts and three key policies:

| | `kypassword-server` | `kybookmarks-server` | `kyrecovery-server` |
|---|---|---|---|
| Key | generated, ≥32 bytes enforced | **a literal survives on the verify/convert path; the write path has no fallback** | HKDF from the keyring |
| Truncation | anchor beside the key | undetectable | sequence numbers in the DB |
| Fields | joined on bare `\|` | joined on bare `\|` | details pre-hashed |

`kybookmarks-server/internal/audit/audit.go:50` keeps a literal,
`"kybookmarks-default-hmac-secret"`, and its write path no longer reaches it —
`loadOrCreateKey` has no constant fallback. What survives is narrower: the literal is what
`legacyHash` verifies v0 entries against, so it can still *recognise* a log an attacker
authored under it. It can no longer launder one. `converge` re-mints under the real key
only when the high-water mark attests to that exact log — same record count and same tail
hash — so a forged log is either refused by the mark or left in the old format for
`Resume`'s digest check to reject. Only a genuine first boot, with no mark at all and every
entry `v: 0`, converts. The key floor is 32 bytes, and on the write path — the one that
mints and checks new records — there is no fallback at all.

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

`Append` takes a `context.Context`, which bounds the wait for the chain lock, not
`persist`. `persist` still runs under the lock — the record and its anchor have to be written together — so give it its own
timeout, and do not call back into the `Chain` from it: the lock is not reentrant, and the
anchor it would ask for is already one of its arguments.

```go
chain, err := auditchain.New(key)          // or Resume(key, lastRecord, anchor)
rec, err := chain.Append(ctx, func(r auditchain.Record, a auditchain.Anchor) error {
    return store.WriteRecordAndAnchor(r, a) // one transaction
}, "login", user)
err = auditchain.Verify(key, records, anchor)
err = auditchain.VerifyStream(key, rows, anchor) // same, for a log too large to hold
```

`VerifyRecord` asks whether a record carries its own digest, and nothing about where it
sits. It also refuses a record numbered zero or carrying a malformed hash, because `Append`
mints neither — a legacy log numbered from zero is exactly what a migration probe hands it.
`Resume` answers a different question — is this the tail — and needs the anchor to do
it. A conversion probe wants the first.

`Replay` builds a chain in memory from field tuples and hands back the records with their
final anchor, for a bulk rewrite that writes the log once. `Append`'s persist parameter
means the chain advances only when the store agrees; passing one that does nothing per
record would satisfy the signature and mean the opposite.

Errors worth an `errors.Is` in a caller: `ErrWeakKey`, `ErrBrokenChain`.

Chains in this suite reach six figures, and the bug that follows from paging them is
specific: `kyrecovery-server`'s `VerifyChain` read a fixed 100000 events and then reported a
sequence gap on a perfectly healthy chain. `VerifyStream` removes the reason to page. A
record yielded with a non-nil error fails the verification rather than ending the walk, so a
store that dies mid-read cannot look like a short chain.

`Anchor` is `{Count, Hash}`, which is exactly `kypassword-server`'s `audit.state` and
`kyrecovery-server`'s `ledger.head`. KyPassword has migrated onto this package. It needed no
version field: its legacy format was a *single* keyed HMAC digest, so `converge` verifies
every entry under that digest and re-mints the whole log under `auditchain`'s in one atomic
rewrite, leaving nothing to distinguish afterwards. The unkeyed variant that preceded it was
deleted rather than carried, because a chain under no secret is one anyone who can write the
log can recompute end to end.

`kybookmarks-server` is the one with two legacy versions, `v: 0` and `v: 1`, and it converts
the same way: a log is re-minted only when it verifies whole under one of them *and* the
mark outside the log attests to it.

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

`HashWith` mints at chosen `Params` — `{Memory, Time, Threads}`, bounded to the same band
`Verify` accepts — for a test suite that cannot afford 64 MiB per derivation. `Hash` is the
suite's answer, calling `HashWith` at `DefaultParams()`, and what production code calls.
`DummyVerify` spends a verification's cost on a reject path that never reached one, so a
missing account does not answer faster than a wrong password — though `ErrBusy` returns
without deriving, so under load that leak reopens.

```go
encoded, err := password.Hash(plaintext)        // "$argon2id$v=19$m=65536,t=3,p=4$..."
ok, err := password.Verify(plaintext, encoded)  // ErrMalformed, never a silent default
stale, err := password.NeedsRehash(encoded)     // upgrade on next successful login
fast, err := password.HashWith(plaintext, password.Params{Memory: 8 * 1024, Time: 1, Threads: 1}) // tests only
```

Errors worth an `errors.Is` in a caller: `ErrBusy`, `ErrMalformed`.

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
seven ways; the five whose behaviour differs materially are:

| Product | On a corrupt key file | First-boot race | fsync |
|---|---|---|---|
| `kynotes-server` | **continues with an empty secret** | unguarded | no |
| `kypassword-server` | **regenerates, orphaning every old record** | unguarded | no |
| `kysignon-server` | refuses to start | unguarded | no |
| `kyrecovery-server` | refuses | `O_EXCL` | no |
| `kypost-server` | refuses | mutex + recheck | yes |

This package refuses rather than guesses: an existing file that does not decode to exactly
the expected size is an error and is left untouched. The key is written to a temporary file
and then `os.Link`ed to its final name, so the cross-process race is settled by `link`
failing with `EEXIST` — not by `O_EXCL`, which would leave a partial file at the real path
that this package then refuses to replace forever. The loser re-reads the winner's key
rather than returning one that was never persisted. The file and its directory are both fsynced, because a crash after first boot
otherwise leaves a zero-length file that the refusal above then reports forever.

`RequireOwnerOnly` is exported separately. Nothing in the suite checked that a key file is
still `0600`, so one relaxed by a stray chmod or a restore kept being used as though it
were secret.

```go
key, err := keyfile.LoadOrCreate(filepath.Join(dir, "audit.key"), 32)
```

`LoadOrCreate` and `Load` are hex; `LoadOrCreateEncoded` and `LoadEncoded` take an
`Encoding` — `Hex`, `Raw` or `Base64` — because four products already wrote their key
files those ways: `kydns-server` writes a raw 32-byte ed25519 seed, `kysignon-server`
writes raw, `kynotes-server` and `kypost-server` write base64. A package that can only read
hex is a package those four cannot adopt.

`Load` never creates. `kypost-server` runs a daemon and an API process against the same
key file, and the daemon must never mint a key the API process did not — when both are
allowed to create, a restart in the wrong order leaves half the data under a key that no
longer exists, and nothing reports it: every write succeeds, and every old read fails as
though the data were corrupt.

`FromEnv` reads a key from an environment variable, hex or base64, and applies the same
*content* checks a file-supplied key gets — the encoding must decode and the result must be
exactly `size` bytes — with set-but-unparseable an error rather than a fall-through to the
file. It cannot apply the rest: a file key also goes through `openKey`'s symlink and
`os.SameFile` checks and `checkKeyInfo`'s ownership and 0600 permission checks, and an
environment variable has no inode to check. Four products check an environment variable before the file; doing that outside this
package means the env-supplied key skips every check the file-supplied one gets.

```go
key, err := keyfile.LoadOrCreateEncoded(path, 32, keyfile.Base64)
key, err := keyfile.Load(path, 32)                       // never creates
key, ok, err := keyfile.FromEnv("KY_AUDIT_KEY", 32)       // ok is false when unset
```

A hex key file is lowercase hex with exactly one trailing newline — 65 bytes for a 32-byte
key. That format is pinned by `TestHexFileFormat`.

`errors.Is` a failed load against `ErrUnreadable` to tell a corrupt key file from a missing
one — the second creates under `LoadOrCreate`, the first never does.

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

Iterations are bounded to 100,000–12,000,000: the value arrives from a client or a stored
record, and unbounded it buys minutes of CPU per login.

The two products do not agree on the ceiling, and this package takes the looser of them.
`kypost-server` enforces 12,000,000 with nothing tighter in front of it. `kynotes-server`'s
derivation carries the same 12,000,000, and four of its five routes that accept a client
iteration count cap it below that — one clamps an out-of-range value to 600,000 rather
than refusing it, the other three refuse anything outside 100,000-1,000,000. Its fifth
route, account recovery, checks the client's count only through the derivation's own
100,000-12,000,000 bound, so kynotes does admit the full ceiling, just not on every route.
**Adopting this package as the only bound would raise those four routes' ceiling
twelvefold.** Which number is right is an open product decision; keep their tighter
checks until it is made.

A ceiling is not admission control, though — it bounds one call and says nothing about how
many run at once, so a modest burst at the ceiling takes every core and starves the handlers
that would have shed it. **Four concurrent slots and a 2-second wait**, past which
`AuthSecret` returns `ErrBusy` — 503, and no lockout strike. PBKDF2 is single-threaded, so a
slot really is a core. The budget is `derive`'s own rather than `password`'s because this
package is standard-library-only by design and importing `password` would pull `x/crypto`
into it. `SyntheticSalt` lower-cases the username, because keying anything off the raw string
lets one account present as many and quietly multiplies any per-account budget above it.

`AuthSecretContext` bounds the wait for a slot. The budget stays separate from
`password`'s — the two bound different resources, and this package importing `password`
would pull `x/crypto` into it — but `derive.MaxConcurrent`, `password.MaxMemoryKiB` and
`password.MaxLanes` are exported so a product running both can add them up.

## Contributing

`.github/workflows/downstream.yml` builds and tests the consumers in its matrix against
your pull request — today `gridlock-server`, `kybookmarks-server` and `kypassword-server`,
the three that import this module. The other six suite repositories do not yet, and are not
watched; adding one is a matrix entry. A breaking change fails there, in your PR, rather
than months later in a product nobody rebuilt.

To land a change that breaks a consumer, open a branch with the same name in the consumer
repository. The job pairs them by branch name and tests the two together.

The job needs a `SUITE_READ_TOKEN` secret with `contents: read` on the organisation.
