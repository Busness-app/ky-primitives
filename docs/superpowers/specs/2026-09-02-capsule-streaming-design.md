# The streaming capsule container

Design, 2026-09-02. No implementation.

`capsule.Seal` takes `[]File` fully in memory and `Open` materialises every member before
it writes any of them. kyrecovery-server captures multi-gigabyte SQLite databases, so it
grew a container of its own. This document decides what replaces it, and whether the
replacement lives here.

Nothing below is implemented. Every safety property stated as a property of the *proposed*
design is untested — the claims register at the end says which claims were measured and
which were not, and no claim appears in this document without one of those two labels.

## Non-goals

- **A general streaming framework.** One container, one payload shape, one extraction path.
- **Reading the retired containers.** kycap/1, kyrecovery's tar, and the streaming
  container described below are all retired unread. Nothing is in the wild.
- **Compression tuning, resumable transfer, or parallel chunk processing.** Each is a
  separate argument and none of them is why this container exists.

---

## Part 1 — What the existing container actually is

Source: `/home/yoshi/busness.app/kyrecovery-server/internal/capsule/stream.go`, 449 lines,
`PackDirectoryStream` and `UnpackToDirectoryStream`.

### Recorded verbatim

**Chunk size.**

```go
const (
	// StreamChunkSize is the size of each encrypted chunk in streaming mode (1 MB)
	StreamChunkSize = 1024 * 1024
)
```

**Per-chunk nonce derivation.** Identical text in both the writer and the reader:

```go
chunkNonce := make([]byte, len(nonce))
copy(chunkNonce, nonce)
binary.BigEndian.PutUint32(chunkNonce[len(chunkNonce)-4:], binary.BigEndian.Uint32(chunkNonce[len(chunkNonce)-4:])^chunkIndex)
```

**Per-chunk AAD.**

```go
aad := fmt.Sprintf("%s:chunk:%d", manifest.AAD, chunkIndex)
```

where `manifest.AAD` is set once, at pack time, to:

```go
AAD: fmt.Sprintf("%s:%s", opts.CapsuleID, opts.ServiceName),
```

**Tar member order.** The outer container is a tar written in this order, so `manifest.json`
precedes the payload by two members:

| # | Member | Mode | Contents |
|---|---|---|---|
| 1 | `manifest.json` | 0644 | `json.MarshalIndent` of the manifest, `Version: 2` |
| 2 | `nonce.bin` | 0644 | the base nonce |
| 3 | `payload.stream.enc` | 0644 | repeated `[4-byte BE ciphertext length][ciphertext]` |

Each chunk's plaintext is a slice of a gzipped tar of the source directory, so there are two
tars: the outer container and the compressed payload inside it.

### Measured behaviour

There is no benchmark. `go test ./internal/capsule/ -run Stream -benchmem -v` matches one
test, `TestStreamingPackAndUnpack`, which passes in 0.02s over a fixture of a few hundred
bytes. `-benchmem` printed nothing because nothing it could measure exists. The constant-
memory claim in the doc comments had never been measured.

Measurements below were taken by copying the repository to `/tmp` and adding a throwaway
test to the copy; `/home/yoshi/busness.app/kyrecovery-server` was not modified and is clean.

**Memory.** Peak `runtime.MemStats.HeapAlloc`, sampled every millisecond:

| Payload | Spool file | Peak heap, pack | Peak heap, unpack |
|---|---|---|---|
| 16 MiB | 8.0 MiB | 4.5 MiB | 16.8 MiB |
| 64 MiB | 32.1 MiB | 5.5 MiB | 62.9 MiB |
| 256 MiB | 128.7 MiB | 5.5 MiB | 266.1 MiB |
| 1024 MiB | 513.8 MiB | 5.6 MiB | 1418.3 MiB |

Unpack's peak heap tracks the payload almost exactly, which reads as a straightforward
refutation of the `O(1) RAM` comment on `UnpackToDirectoryStream`. It is not one. Re-run
under `GOGC=off GOMEMLIMIT=64MiB`, the same four payloads complete with peak heap 44.2,
54.8, 51.8 and 50.8 MiB — flat from 256 MiB of payload upward. The 1418 MiB figure is
garbage the collector had not been asked to reclaim, not bytes the container was holding.
The reader allocates a fresh 1 MiB `cipherChunk` and a fresh plaintext buffer per chunk, so
a 1 GiB restore churns roughly 2 GiB of garbage and default `GOGC=100` lets the heap grow
to meet it.

So the claim holds, with two qualifications that the replacement has to answer:

1. **Live memory is constant; resident memory is not, by default.** A restore on a memory-
   constrained host reaches ~1.4x the payload in RSS unless `GOMEMLIMIT` is set. Reusing one
   chunk buffer instead of allocating per chunk removes the churn rather than managing it.
2. **Pack is constant memory only if `TMPDIR` is disk-backed.** `PackDirectoryStream` spools
   the entire gzipped payload through `os.CreateTemp("", "kyrecovery-payload-*.tmp")` before
   it encrypts anything — measured at 513.8 MiB for a 1 GiB payload. On this host `/tmp` is
   a tmpfs and `TMPDIR` is unset, so that spool is resident memory that the Go heap
   measurement cannot see. The container's headline property is contingent on a deployment
   detail it neither documents nor checks.

   Read the 513.8 MiB as a floor, not a typical case. The fixture was half incompressible
   bytes and half zeros, so it gzipped to about 0.5x. A real SQLite capture is binary pages
   that compress far less, approaching 1.0x, so the honest figure for kyrecovery's actual
   workload is that **a 1 GiB database spools about 1 GiB** — into RAM, on any host whose
   `/tmp` is a tmpfs. That is the whole payload the container exists to avoid holding.

**Tamper resistance.** Each row rewrites one member of a packed capsule and re-opens it:

| Attack | Result |
|---|---|
| Swap chunks 0 and 1 | refused — `streaming decryption chunk authentication failed` |
| Drop chunk 1 | refused — `streaming decryption chunk authentication failed` |
| Duplicate chunk 0 | refused — `streaming decryption chunk authentication failed` |
| Truncate: drop the last chunk | refused — `unexpected EOF` |
| Rewrite `manifest.json`, leave `aad` | **accepted** |
| Chunk length header `0xFFFFFFFF` | refused, after attempting a 4 GiB allocation |

Three findings follow, and they are what the design has to fix rather than inherit.

**The manifest is not authenticated.** `service_name`, `capsule_id`, the entire `files`
list and `payload_hash` were rewritten — emptying the file list and setting the hash to
`"00"` — and the capsule unpacked successfully and returned the rewritten manifest to the
caller. Only the `aad` field is pinned, because it is the string the chunks were sealed
under; every other field is decoration. `payload_hash` is never verified on this path at
all. This is the same defect the README's retirement table attributes to the two containers
it does list, present in a third container the table does not mention.

**Truncation is refused by accident.** The reader's loop breaks cleanly on `io.EOF` *and*
`io.ErrUnexpectedEOF`, then closes the pipe without error. Nothing in the capsule format
records how many chunks there should be. The refusal comes from gzip failing to find its
trailer, one layer below the crypto — a real defence, but one supplied by a compression
format that was not asked to provide it, and which a future change to the payload encoding
would silently remove.

**The chunk length prefix is unauthenticated and unbounded.** `chunkLen :=
binary.BigEndian.Uint32(lenBuf)` followed immediately by `make([]byte, chunkLen)` lets any
capsule file on disk demand a 4 GiB allocation before a single tag is checked.

**Reorder, drop and duplicate are genuinely refused**, and the reason is the part worth
keeping: the chunk index is bound into both the nonce and the AAD, so a chunk moved to
another position is opened under the wrong nonce and the wrong AAD and fails twice over.

---

## Part 2 — The three questions

### Q1. Can the manifest be authenticated before the first byte is written?

**Yes for the manifest, no for the payload's completeness, and the two need different
answers.**

kycap/2 already carries the shape: the manifest's exact bytes are the AAD, so opening any
ciphertext sealed under them proves they were not edited. Carry that into the stream by
making the header manifest the AAD of *every* record. The reader then opens record 0 before
it writes anything, and a successful open is proof the manifest is the one that was sealed.
The cost is one chunk of read-ahead — 1 MiB — and no staging.

The wrong answer that looks fine is to stop there. Authenticating the manifest proves what
the capsule *says it is*; it says nothing about whether the payload arrived whole. A
truncated stream still authenticates every record it does contain, and by the time the
reader runs out of input it has already written most of a database. So a second mechanism
is needed, and this is where the brief's staging-versus-space trade-off bites.

**Decision: stage into a sibling directory on the target's own filesystem and rename on
success.** Not a temporary directory elsewhere, and not writing straight into the target.

The reasoning is that the usual objection to staging — that it costs the disk space
streaming was meant to save — is only true when the staging area is on a different
filesystem, because then the commit is a copy. Staged into a sibling of `targetDir`, the
bytes are written exactly once, to the filesystem they were always going to land on, and
the commit is a rename. `extract.go` already requires the target to be empty or absent, so
the rename has either no destination or an empty one.

What this costs honestly:

- The parent of `targetDir` must be writable, which it was not previously required to be.
- Staging and target must share a filesystem for the rename to be atomic. If `targetDir`
  is a mount point, the sibling is on the parent filesystem and the rename crosses it. The
  implementation must detect this and refuse rather than silently fall back to a copy.
- A crash between the last chunk and the rename leaves a staging directory behind. It is
  named predictably and refused-then-removed on the next attempt; it is never adopted.

Compared to the existing container, which writes into the target as it decrypts and leaves
whatever it wrote when gzip finally objects, this is the property being bought: **a restore
either produced the whole capsule or produced nothing.** *(Proposed. Untested.)*

`extract.go`'s existing `rollback` stays as the in-process cleanup for the staging
directory; the rename is what makes the outcome atomic rather than best-effort.

### Q2. What stops a chunk being reordered, dropped, duplicated or truncated?

Reorder, drop and duplicate are already solved in the existing container and the mechanism
is kept: **the record index is bound into the nonce and into the AAD.** Truncation is not
solved there and needs the terminator the brief asks for.

Proposed record format — every record is
`[1-byte type][4-byte BE ciphertext length][ciphertext]` with:

- **nonce** = `baseNonce[0:8] || uint32BE(index)`. Explicit concatenation, not the existing
  XOR into the base nonce's last four bytes. The XOR is not broken — distinct indices always
  XOR to distinct nonces — but the index is a computed property of the nonce rather than a
  visible field, and a reviewer has to prove uniqueness instead of reading it.
- **AAD** = `manifestBytes || type || uint64BE(index)`.
- **type** = `0` for a data record, `1` for the trailer. Bound into the AAD, so a data
  record cannot be presented as a trailer or the reverse.

The trailer is the terminator, and it is inside authenticated data. It is a record like any
other, sealed at index `n` where `n` is the number of data records, whose plaintext is a
small JSON object carrying `payload_hash`, `payload_size`, `chunk_count` and the per-file
`FileEntry` list. The reader requires a type-1 record before EOF and refuses trailing bytes
after one.

How each attack is refused *(all proposed; none tested)*:

| Attack | Refused by |
|---|---|
| Reorder | Record at position *j* is opened under nonce *j* and AAD index *j*; its tag was computed under *i*. AEAD failure. |
| Drop | Every subsequent record shifts index, so the first one after the gap fails as above. The trailer's `chunk_count` also disagrees with the count observed. |
| Duplicate | The copy occupies a position whose index it was not sealed under. AEAD failure. |
| Truncate | The trailer is missing, and the reader requires one. A forged trailer needs the key. This is a refusal by the capsule format, not by gzip's trailer. |
| Extend | The reader stops at the trailer and refuses bytes after it. A further record would in any case need a tag under an index the writer never used. |
| Trailer lifted from another capsule | That capsule's manifest bytes are in the AAD and differ. AEAD failure. |
| Data record relabelled as the trailer | `type` is in the AAD. AEAD failure. |
| Oversized length prefix | Bounded at `chunkSize + tagSize` and checked before allocation. |

The length prefix is the one unauthenticated field on the wire. It is bounded before it is
used, and a value that is wrong but within bounds yields a ciphertext that fails its tag, so
it cannot do worse than turn a valid capsule into an invalid one. A fixed-size framing with
no length prefix at all was considered — deriving the last record's length from an
authenticated `payload_size` — and rejected because `payload_size` is not known until the
payload has been written, which is the same problem the trailer exists to solve.

`payload_hash` remains the backstop `container.go` already calls load-bearing: a wrong-but-
valid key, or a Shamir reconstruction that produces plausible bytes, is caught by the hash
even where every tag verified. It is checked against the streamed plaintext before the
staging directory is renamed.

**Three fields move out of the header manifest and into the trailer, and this is a real cost.**
`payload_hash`, `chunk_count` and the `Files` list are all derived from content, and a
one-pass streaming writer does not know any of them when it writes the header. The
alternatives were:

| Option | Rejected because |
|---|---|
| Spool the payload first, then write the manifest | What the existing container does. Costs 1x the *gzipped* payload in `TMPDIR` — 513.8 MiB for a 1 GiB half-compressible fixture, and approaching the full 1 GiB for a real SQLite capture, resident wherever `/tmp` is a tmpfs. |
| Two passes over the source: hash, then encrypt | The source is a live SQLite database. Anything written between the passes yields a capsule whose manifest disagrees with its payload, discovered at restore time. A TOCTOU with a recovery kit on the far side of it. |
| Trailer (chosen) | `ReadUnverifiedManifest` on a stream container cannot report the file list or the payload hash without reading to the end. |

The division is coherent: **the header says what the capsule is, the trailer says what it
contains.** The header keeps `capsule_id`, `service_name`, `app_version`, `created_at`,
`threshold`, `total_shares`, `dependencies` and `verification_recipe` — everything a
custodian needs to identify a capsule and find its kit, all of it authenticated by every
record. `OpenStream` assembles both halves and returns a `Manifest` only on success,
preserving the existing rule that only a successful open produces one.

### Q3. Does this belong in `ky-primitives` at all?

**The case for leaving it in kyrecovery is strong and should be stated at full strength.**

The library's bar is that divergence between copies must silently corrupt or lose recovery
data. Streaming does not obviously clear it. Grepping all seventeen repositories in
`/home/yoshi/busness.app` for `StreamChunkSize`, `PackDirectoryStream` or
`payload.stream.enc` matches files in exactly one: kyrecovery-server. *(Measured.)* One
product, one container, no second copy in existence to drift from the first. That is the
opposite of `shamir`, which earned its place because two incompatible GF(2^8) fields already
existed and cross-combining them returned garbage silently.

It gets worse for the library. There is no streaming consumer here today and there will not
be one until Plan 5. `FileSource` is being designed to serve exactly one directory walk.
Every one of the three defects measured in Part 1 — the unauthenticated manifest, the
unbounded allocation, the weak extraction — is fixable inside kyrecovery in far less code
than a new container, immediately, without blocking `v0.2.0`. And a wire format adopted here
is one the library supports forever, chosen before any second product has voted on its
shape. "We might need it elsewhere" is not evidence, and this library's own scope note says
so.

**It is nonetheless wrong, because the second copy already exists — inside kyrecovery.**

Not in the containment. It is worth being exact about this, because the obvious version of
the claim is false: `extractTarReaderToDir` has no `os.Root`, refuses no entry types, clamps
no modes and applies no budgets — but neither does `ExtractToDirectory`, which serves the
non-streaming path. Both call the same `SafeJoin`, both hardcode `0600`. Neither ever had
the hardening in this library's `extract.go`, so neither *lost* it, and a divergence needs
something that diverged.

The divergence is in **verification**, and it is measurable:

| | `Unpack` (non-streaming) | `UnpackToDirectoryStream` |
|---|---|---|
| `payload_hash` verified | yes, `capsule.go:254-259` | **no** |
| Per-file SHA-256 against `manifest.Files` | yes, `capsule.go:291-298` | **no** |
| Missing member named in the manifest | refused | not checked |

Both are entry points to the same package, reading the same capsules, and they disagree
about whether a capsule's own manifest is checked against its own payload.

`stream.go:341` closes the trap. The streaming reader's header scan breaks on either
`payload.stream.enc` or `payload.enc`, and when it finds the latter it decrypts the whole
blob and hands it to `extractTarReaderToDir` — so an ordinary non-streaming capsule, the
exact bytes `Unpack` would have hash-checked twice over, is extracted with no payload hash
check and no per-file digest check at all. Which verification a capsule receives is decided
by which function the caller happened to call, and the streaming reader's own branch is
dispatched on a tar member name that anyone holding the file can rename. There is a third
level below both: if the scan finds no manifest, nonce or payload it falls back to `Unpack`,
which verifies everything. One package, one capsule, three verification levels.

That is precisely the failure the bar describes — two copies of one refusal, one of which
stopped matching the other — and it did not need two repositories to happen. It is also
squarely about recovery data: an unverified per-file digest is how a corrupt restore reaches
a custodian looking correct.

Plan 5 sharpens it rather than resolving it. If kyrecovery adopts this library's `Open` for
ordinary capsules and keeps `UnpackToDirectoryStream` for large ones, the same product ships
two capsule readers with two different answers to the same question: `TestOpenRejectsATamperedManifest`
proves the library's reader refuses a rewritten manifest, and Part 1 measures the streaming
reader accepting one. Whether a custodian's manifest can be trusted would depend on how big
the database was.

And the asset that must not be copied is not the container — it is `extract.go`. The
`os.Root` walk, the traversal and entry-type refusals, the duplicate-destination check, the
non-empty-target refusal and the owner-only mode clamp are the strongest hardening in the
suite. A *correct* streaming extractor in kyrecovery would be a verbatim copy of all of it.
The container is thin; the containment is the thing, and the containment already has two
callers.

**Decision: build it here.** Scoped as follows.

| | |
|---|---|
| **What is built** | One streaming container, sharing kycap/2's manifest type and `extract.go`'s containment. Not a streaming framework. |
| **When** | Its own plan, ahead of Plan 5. Not in `v0.2.0`; Tasks 1-14 ship without it. |
| **If we are wrong** | ~300 lines of container carried here for one product. Cheap, and deletable. |
| **If the other choice were wrong** | A hardened streaming extractor in kyrecovery becomes a hand-copy of `extract.go` in a repo where nobody is comparing the two — the shamir failure, on the restore path. |
| **Interim** | The unbounded `make([]byte, chunkLen)` is a live denial of service reachable from any capsule file on disk. If Plan 5 slips, bound it in kyrecovery without waiting. |

The costs are asymmetric and that is what settles it, not the count of copies.

---

## Part 3 — Proposed API

All of Part 3 is proposed. None of it is implemented and none of the properties it claims
have been tested.

### Source

```go
// SourceFile is one member of a streaming payload. Content is not held; Open is called
// when the sealer reaches this member and the result is closed before the next Open.
type SourceFile struct {
	Path string
	Mode os.FileMode
	Open func() (io.ReadCloser, error)
}

// FileSource yields a payload's members in order. It is iterated exactly once.
type FileSource = iter.Seq2[SourceFile, error]

// DirSource walks root and yields its regular files, relative to root.
func DirSource(root string) FileSource
```

`iter.Seq2[T, error]` is the idiom `auditchain.VerifyStream` already uses for a streamed
sequence that can fail partway, so this is the library's existing shape rather than a new
one.

`SourceFile` deliberately carries no `Size`. The sealer learns each member's length by
reading it, and a declared size that disagrees with the bytes is a defect the type does not
need to make possible. `DirSource` exists so that the walk is written once: kyrecovery's
current walk sets `Mode: int64(info.Mode())` and hands `os.FileMode`'s type bits to
`tar.Header.Mode`, which is the kind of thing a shared helper stops repeating.

### Seal and Open

```go
// SealStream writes a kycap/2-stream container to w and returns the key that opens it.
// Memory is bounded by the chunk size regardless of payload size; the payload is never
// spooled.
func SealStream(w io.Writer, serviceName, appVersion string, src FileSource,
	deps, recipe map[string]any, threshold, totalShares int) (key []byte, m Manifest, err error)

// OpenStream reads a kycap/2-stream container from r, extracts it under targetDir with the
// containment in extract.go, and returns the authenticated manifest. targetDir must be
// empty or absent and its parent must be writable. maxTotalBytes bounds the expanded
// payload and must be greater than zero.
func OpenStream(r io.Reader, key []byte, targetDir string, maxTotalBytes int64) (Manifest, error)
```

`SealStream` writes to an `io.Writer` rather than returning bytes, which is the difference
from `Seal` that matters; everything else in the signature is `Seal`'s, so the two are
readable side by side. `maxTotalBytes` is explicit and required because streaming exists to
exceed `extract.go`'s 256 MiB budget, and a limit that cannot be set is either too small for
kyrecovery or too large for everyone else. A refusal to guess free disk space from the
limit: running out of space is already an error, and it unwinds the staging directory.

### Wire layout

```
"kycap/2s\n"                    9 bytes, magic
uint32BE hdrLen                 4 bytes, bounded by maxManifestBytes (1 MiB)
manifest JSON                   hdrLen bytes — the exact bytes, and the AAD for every record
baseNonce                       8 bytes

record 0        [type=0][uint32BE len][ciphertext]     nonce = baseNonce || uint32BE(0)
...
record n-1      [type=0][uint32BE len][ciphertext]
record n        [type=1][uint32BE len][ciphertext]     the trailer
```

Each data record's plaintext is up to 1 MiB of the gzipped tar of the payload — the same
plaintext shape `Seal` produces, so one extraction serves both containers. The trailer's
plaintext is JSON: `payload_hash`, `payload_size`, `chunk_count`, `files`.

`hdrLen` and `baseNonce` are unauthenticated but self-checking: a wrong `hdrLen` yields
different manifest bytes and record 0 fails; a wrong `baseNonce` yields a wrong nonce and
record 0 fails. `hdrLen` is bounded before it is read, as `parseContainer` already bounds the
manifest.

The magic is a distinct string, so `Open` and `OpenStream` refuse each other's containers
with `ErrUnknownContainer` rather than misparsing them. Sniffing the magic to dispatch
automatically was considered and rejected: `Open` returns files in memory and `OpenStream`
cannot, so one function that silently does either is one whose memory behaviour depends on
its input.

### Reusing extract.go's containment

The requirement is that the refusals exist once. Concretely, `extractPayload` is split
rather than copied:

- **Shared, unchanged in behaviour:** `safeRelPath`, the `tar.TypeReg`-only entry check, the
  duplicate-destination check, the owner-only mode clamp, `prepareTargetDir`'s `os.Root`
  handle and non-empty-target refusal, `writeInto`'s `O_EXCL`, and `rollback`.
- **Changed once, for both callers:** `writeInto` takes an `io.Reader` and a per-member
  limit instead of a `[]byte`. `Open` is re-expressed on top of it; the streaming reader
  uses the same function. This is the only way `OpenStream` avoids accumulating `[]File`,
  which is exactly what makes `Open` proportional to its payload.
- **Parameterised, not duplicated:** `maxCapsuleFiles`, `maxCapsuleFileBytes` and
  `maxCapsuleExpandedTotal` become fields of a limits value that the one extractor takes.
  `Open` passes today's 4096 / 64 MiB / 256 MiB. `OpenStream` passes 4096 and
  `maxTotalBytes`. The numbers differ; not one line of refusal does.
- **Added:** `prepareTargetDir` gains the staging sibling and the same-filesystem check from
  Q1, and a commit step that renames it into place. Both callers get it, so an ordinary
  `Open` becomes atomic too — an improvement it did not previously have.

`extractTarReaderToDir` and `SafeJoin` are deleted along with the rest of kyrecovery's
container when Plan 5 lands — not because they diverged from `ExtractToDirectory`, which
they did not, but because a streaming reader hardened in place would have had to become a
verbatim copy of `extract.go`. Deleting them is how that copy never gets written.

---

## Claims register

Every safety-relevant statement above, labelled. **M** was measured by running something;
**P** is proposed and has never been executed. Nothing in this document is both.

| # | Claim | | Evidence, or what must test it |
|---|---|---|---|
| 1 | The existing container's chunk size is 1 MiB, its nonce is the base nonce XOR the index in the last four bytes, its AAD is `"<capsule_id>:<service_name>:chunk:<n>"`, and `manifest.json` precedes `payload.stream.enc` in the tar | M | Read from `stream.go`, quoted verbatim in Part 1 |
| 2 | The existing container has no benchmark; its constant-memory claim was never measured | M | `go test ./internal/capsule/ -run Stream -benchmem -v` reports one test and no benchmarks |
| 3 | The existing container holds constant *live* memory: ~51 MiB peak heap at 1 GiB of payload, flat from 256 MiB up | M | `GOGC=off GOMEMLIMIT=64MiB`, payloads 16/64/256/1024 MiB |
| 4 | Its *resident* memory reaches ~1.4x payload under default GC settings | M | Same harness, default `GOGC`: 1418.3 MiB peak heap at 1024 MiB payload |
| 5 | Its pack path spools 1x the gzipped payload to `os.TempDir()`, which is a tmpfs on this host with `TMPDIR` unset | M | 513.8 MiB spool for a 1024 MiB payload that gzipped to ~0.5x; a less compressible real capture approaches 1.0x. `findmnt -no FSTYPE /tmp` reports `tmpfs` |
| 6 | It refuses chunk reorder, drop and duplicate | M | Rewritten capsules; all three fail with `streaming decryption chunk authentication failed` |
| 7 | It refuses truncation only via gzip's missing trailer, not via the capsule format | M | Dropping the last chunk fails with `unexpected EOF`; no chunk count exists anywhere in the format |
| 8 | It **accepts** a rewritten manifest, including an emptied `files` list and a bogus `payload_hash` | M | Rewrote `manifest.json` leaving `aad` intact; unpack succeeded and returned the rewritten manifest |
| 9 | It will attempt a 4 GiB allocation from an unauthenticated length prefix | M | Chunk length header set to `0xFFFFFFFF` |
| 10 | Exactly one repository in the suite contains a streaming container | M | Grep for `StreamChunkSize`/`PackDirectoryStream`/`payload.stream.enc` across seventeen repos; only kyrecovery-server matches |
| 11 | `Unpack` verifies `payload_hash` and every per-file SHA-256; `UnpackToDirectoryStream` verifies neither, and routes non-streaming `payload.enc` capsules through the unverified path | M | `capsule.go:254-259` and `capsule.go:291-298` against `stream.go:341`. Neither kyrecovery path has `os.Root`, entry-type refusals or budgets — that is common to both and is not a divergence |
| 12 | The proposed reader authenticates the manifest before writing any byte | P | A test that rewrites the header manifest and asserts the target is untouched, not merely that the call failed |
| 13 | The proposed reader refuses reorder, drop, duplicate, truncate, extend, a lifted trailer and a relabelled record | P | Seven tests, one per row of the Q2 table. The truncate test must assert the failure survives replacing gzip with a stored-mode payload |
| 14 | A failed or truncated restore leaves the target exactly as it was | P | A test that fails mid-stream and asserts the target is absent or empty, plus one that asserts the staging sibling is not adopted on retry |
| 15 | The rename commit is atomic, and a cross-filesystem target is refused rather than silently copied | P | A test with `targetDir` as a mount point. Until it exists, this is the claim most likely to be wrong |
| 16 | `SealStream` holds memory bounded by the chunk size and never spools | P | A benchmark across payload sizes under `GOMEMLIMIT`, asserting flatness — the measurement the existing container never had |
| 17 | `Open` and `OpenStream` apply identical refusals | P | The existing `extract.go` tests, run against both readers from one table. If the table is duplicated, this design failed at the thing it was for |

## Follow-ups this design does not do

- **The README's retirement table lists two retired containers and not this third one.**
  It should list `version: 2` / `payload.stream.enc` alongside kycap/1 and kyrecovery's tar,
  with the same column filled in: it authenticated its ciphertext and its own `aad` string,
  and claim 8 measures what that leaves editable. Not changed here; this task ships one
  document.
- **The interim bound on `chunkLen` in kyrecovery**, per Q3. Independent of this design.
- **The implementation plan.** Written after this recommendation is accepted or rejected.
