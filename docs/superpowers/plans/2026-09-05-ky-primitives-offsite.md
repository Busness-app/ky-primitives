**Repo:** ky-primitives

# ky-primitives/offsite Implementation Plan

**Goal:** Publish a nested Go module, `github.com/Busness-app/ky-primitives/offsite`, that gives KyRecovery, KyNotes, and KyPost one implementation of S3, SFTP, SMB 2/3, and local-file replication without admitting those transports' dependencies into the root module.

**Architecture:** The nested module owns connection parsing, credential-safe target identity, bounded transport I/O, atomic writes where the protocol supports them, reads, and writable-target probes. Products own target persistence, credential sealing, scheduling, audit and sync logs, and the decision about which bytes to replicate. Every transport implements one small `Target` interface and normalizes a missing object to `os.ErrNotExist`.

**Source:** myslop folder `ky-primitives-offsite`, post 233. Reference implementation: `kyrecovery-server/internal/replication` on master. The earlier durable hand-off is `kynotes-server/docs/superpowers/plans/2026-09-05-ky-primitives-offsite.md`.

## Decisions and corrections made while planning

- `offsite/` is a nested module because SFTP needs `github.com/pkg/sftp` and `golang.org/x/crypto/ssh`, and SMB needs `github.com/hirochachacha/go-smb2`. Root consumers must not inherit these requirements.
- Root `nodeps_test.go` does manually walk into nested modules. It must explicitly skip any directory containing a nested `go.mod`; merely adding `offsite/go.mod` is not sufficient.
- The current SFTP suite uses an in-process server. The current SMB suite does not: round-trip and bad-password coverage require `KYRECOVERY_SMB_TEST`. Preserve that opt-in integration test, and keep endpoint and timeout tests hermetic.
- Replica names are relative slash-separated paths. Reject empty names, absolute paths, `.`/`..` components, backslashes, and NULs before any transport sees them. This keeps `file`, SFTP, and SMB from escaping their configured root and gives all four targets one naming contract.
- `Test` uses the fixed name `.ky-offsite-ping`. Local, SFTP, and SMB remove it. S3 may overwrite the same object because the public interface deliberately has no general delete operation.
- Release the library before changing consumers. KyRecovery is the compatibility proof; KyNotes and KyPost adopt only the tagged module.

## Public contract

```go
package offsite

type Target interface {
	Put(ctx context.Context, name string, r io.Reader, size int64) error
	Get(ctx context.Context, name string) (io.ReadCloser, error)
	Test(ctx context.Context) error
}

type Config struct {
	URL        string
	AccessKey  string
	Secret     string
	HostKey    string
	S3Endpoint string
	S3Region   string
	Timeout    time.Duration
}

func Parse(Config) (Target, error)
func Key(Config) string

type UnknownHostKeyError struct { Fingerprint string }
func ParseSMBEndpoint(endpoint, share, dir string) (addr, outShare, outDir string, err error)
```

URL forms:

- `s3://bucket/prefix`: `AccessKey` and `Secret` are required together; `S3Region` defaults to `us-east-1`; blank `S3Endpoint` selects AWS virtual-hosted style. Explicit endpoints must use HTTPS, including MinIO; HTTP endpoints are rejected.
- `sftp://user@host:22/dir`: username-only userinfo is allowed; a URL password is rejected. `AccessKey` supplies the user when the URL omits it. `HostKey` is always required to connect, with `UnknownHostKeyError` carrying the presented fingerprint during `Test`.
- `smb://host/share/dir`: credentials stay in `AccessKey` and `Secret`; all userinfo is rejected. `AccessKey` may be `DOMAIN\\user`.
- `file:///absolute/path`: credentials and a non-empty URL host are rejected.

`Key` returns a stable, credential-free identity derived from normalized target location and non-secret routing fields. It never includes URL userinfo, `AccessKey`, `Secret`, or `HostKey`. Add golden tests before consumers use it as a database key.

## Task 1: Establish the nested-module boundary

**Files:**

- Create `offsite/go.mod` and `offsite/go.sum`.
- Create `offsite/doc.go`.
- Modify `nodeps_test.go`.
- Create `offsite/nodeps_test.go`.

Steps:

- [ ] Add module path `github.com/Busness-app/ky-primitives/offsite` with the same Go directive as the root module. Start with the exact SFTP, SMB, and `x/crypto` versions used by KyRecovery at implementation time; do not add them to the root `go.mod`.
- [ ] Change the root filesystem walk to skip a directory, other than `.`, when that directory contains its own `go.mod`. Add a fixture/helper-level test that proves nested-module Go files are excluded while ordinary new root packages remain covered.
- [ ] Add an offsite dependency-budget test that permits only `go-smb2`, `pkg/sftp`, `x/crypto`, and their transitive requirements. Reject `replace` directives so a local checkout cannot silently define the release.
- [ ] Document the package boundary and the absolute no-guest invariant. Although the current client verifies the final SESSION_SETUP response before adopting its flags, prefer a patched dependency that also rejects a signed final guest/null flag when signing is required.
- [ ] Verify from the repository root and nested module: `go test ./...`; `(cd offsite && go test ./...)`.

## Task 2: Define parsing, identity, and path safety

**Files:**

- Create `offsite/offsite.go`.
- Create `offsite/offsite_test.go`.

Steps:

- [ ] Write table tests for every supported URL, default port and region, escaped path, IPv6 host, unsupported scheme, missing bucket/share/user/credentials, URL password, SMB userinfo, and invalid file URL.
- [ ] Write `Key` tests proving credential changes do not change identity, location changes do, and returned keys contain none of the supplied secrets or usernames.
- [ ] Write name-validation tests for nested relative names and all traversal/absolute-path forms, including Windows separators even when tests run on Unix.
- [ ] Implement `Parse` as strict scheme dispatch. Keep concrete target types unexported unless a consumer has a demonstrated need to construct one directly.
- [ ] Reject non-positive explicit timeouts. A zero timeout means the package default five-minute whole-operation budget.
- [ ] Run `go test ./... -run 'Parse|Key|Name|Config'` inside `offsite/`.

## Task 3: Implement the local target

**Files:**

- Create `offsite/local.go`.
- Create `offsite/local_test.go`.

Steps:

- [ ] Test `Put`, replacement, nested names, 0600 final mode, cleanup after a failed copy, and refusal to escape the configured root.
- [ ] Implement `Put` with `MkdirAll(0700)`, a temporary file in the destination directory, `Sync`, `Close`, `Chmod(0600)`, then rename. Remove the temporary file on every error.
- [ ] Implement `Get` with `os.Open`; preserve `errors.Is(err, os.ErrNotExist)`.
- [ ] Implement `Test` by writing and removing `.ky-offsite-ping` through the same safe write path.
- [ ] Run `go test -race ./... -run Local` inside `offsite/`.

## Task 4: Lift and test S3 SigV4

**Files:**

- Create `offsite/s3.go`.
- Create `offsite/s3_test.go`.

Steps:

- [ ] First add hermetic TLS-server tests for AWS virtual-hosted URLs and explicit path-style endpoints, seekable and streaming PUT bodies, prefix escaping, bounded error bodies, cancellation, accepted success statuses, HTTPS-only endpoint validation, and redirect refusal. Use an unexported transport seam to trust the test certificate; production never accepts HTTP.
- [ ] Install `CheckRedirect` that refuses every redirect and prove 307/308 responses are not followed, so signed request bodies and credentials never move to a server the operator did not configure.
- [ ] Make signing time and HTTP transport injectable only through unexported test seams. Add deterministic golden assertions for PUT and GET canonical requests/authorization rather than checking only that a header exists.
- [ ] Lift PUT without reading seekable inputs into memory. Treat a negative size as invalid; for a non-seekable reader, buffer once and derive the actual size and hash.
- [ ] Add signed GET with `x-amz-content-sha256: UNSIGNED-PAYLOAD`. Return the response body directly on success, map 404 (including `NoSuchKey`) to `os.ErrNotExist`, and close all non-success bodies.
- [ ] Implement `Test` as a PUT to `.ky-offsite-ping` using the ordinary operation budget.
- [ ] Run `go test -race ./... -run S3` inside `offsite/`.

## Task 5: Lift SFTP without weakening host authentication

**Files:**

- Create `offsite/sftp.go`.
- Create `offsite/sftp_test.go`.

Steps:

- [ ] Port KyRecovery's in-process SSH/SFTP server and its stalled-server tests before moving implementation code.
- [ ] Preserve structural PEM detection so whitespace-prefixed private keys are parsed as keys and are never offered as passwords.
- [ ] Preserve fail-closed host verification. An empty pin may dial only far enough for `Test` to return `UnknownHostKeyError`; it never opens an SFTP session or transfers data. A mismatch reports both fingerprints and refuses the session.
- [ ] Keep the five-minute whole-operation budget, including dial, handshake, transfer, rename, and cleanup. Context cancellation must close the underlying connection to release stalled I/O.
- [ ] Implement atomic PUT with `.part` plus `PosixRename`, removing partial files after copy or close failures.
- [ ] Implement GET with `client.Open`; return a wrapper whose `Close` closes the remote file, SFTP client, SSH connection, and timeout context exactly once. Map the server's missing-file status to `os.ErrNotExist` without mapping permission or transport failures.
- [ ] Add in-process round-trip, replacement, cleanup, missing-file, cancellation, unknown-key, mismatched-key, and PEM-not-password tests.
- [ ] Run `go test -race ./... -run SFTP` inside `offsite/`.

## Task 6: Lift SMB with an explicit integration-test boundary

**Files:**

- Create `offsite/smb.go`.
- Create `offsite/smb_test.go`.

Steps:

- [ ] Port table tests for bare host, custom port, UNC, slash, and `smb://` forms. Reject all userinfo before path splitting so passwords containing slashes or backslashes cannot leak through parsing or errors.
- [ ] Preserve SMB 2/3-only behavior and `RequireMessageSigning: true`, domain parsing, whole-operation timeout, `.part` upload, and replace-via-remove-then-rename semantics.
- [ ] Pin a patched dependency (or a released version containing the hardening) that checks final successful SESSION_SETUP flags and rejects guest/null sessions when signing is required. Add an authenticated server regression returning a signed guest final response; `Test` and `Put` must fail before mounting a share. This is an absolute transport invariant, not a claim that an unauthenticated peer can forge the verified response.
- [ ] Make an existing-destination replacement failure explicit: if removal succeeds but rename fails, return the error and remove the partial file; document that SMB cannot provide the same atomic replacement guarantee as local/SFTP.
- [ ] Implement GET with `share.Open` and a closer that unmounts, logs off, closes the connection, and cancels the budget exactly once. Map only an SMB not-found status to `os.ErrNotExist`.
- [ ] Keep hermetic parsing and stalled-server tests in ordinary CI. Port the live round-trip, bad-password, replacement, and missing-file cases behind `KY_OFFSITE_SMB_TEST="host:port/share|user|password"`; do not describe skipped tests as CI proof.
- [ ] Run `go test -race ./... -run SMB`; when credentials are available, repeat with `KY_OFFSITE_SMB_TEST` set.

## Task 7: Prove the cross-transport contract

**Files:**

- Create `offsite/contract_test.go`.
- Modify transport tests only as needed.

Steps:

- [ ] Define reusable contract cases for Put/Get round trip, replacement, nested name, cancellation, and `errors.Is(err, os.ErrNotExist)`.
- [ ] Run the contract against local and hermetic S3/SFTP on every test run, and against SMB when its integration environment is configured.
- [ ] Test that `Test` uses exactly `.ky-offsite-ping` and never a KyRecovery-specific filename.
- [ ] Confirm returned readers remain usable until `Close`, and add leak-sensitive assertions that each test server observes connection teardown.
- [ ] Run `go test -race -count=1 ./...` inside `offsite/`.

## Task 8: Add CI and release documentation

**Files:**

- Modify `.github/workflows/ci.yml`.
- Modify `README.md`.
- Create `offsite/README.md` if examples would otherwise overwhelm the root README.

Steps:

- [ ] Add a Linux/macOS and pinned/stable Go matrix for `(cd offsite && go build ./... && go vet ./... && go test -race -count=1 ./...)`.
- [ ] Add a formatting check for the nested module and run `govulncheck` with `working-directory: offsite`. Keep the root checks unchanged and green.
- [ ] Document URL forms, credential placement, host-key enrollment, timeout behavior, missing-object semantics, enforced SMB signed-session behavior, and the separate module tag namespace.
- [ ] Document release commands and consumer syntax: create repository tag `offsite/v0.1.0`; consumers require module `github.com/Busness-app/ky-primitives/offsite` with `go get github.com/Busness-app/ky-primitives/offsite@v0.1.0`.
- [ ] Run root and nested-module build, vet, race tests, formatting checks, and vulnerability checks locally before opening the PR.

## Task 9: Migrate KyRecovery as the compatibility proof

**Repository:** `kyrecovery-server`, in a separate PR after `offsite/v0.1.0` exists.

Steps:

- [ ] Add the tagged nested module and remove direct SFTP/SMB requirements only after `go mod tidy` proves no other package imports them.
- [ ] Keep `internal/replication/manager.go`, target rows, credential sealing, sync logs, ledger writes, and server handlers. Delete the four transport implementations after the manager builds `offsite.Config`, calls `offsite.Parse`, and uses `Put`/`Test`.
- [ ] Preserve the existing database-to-URL mapping exactly: target type, endpoint, bucket/share, region, prefix, username, secret, and host pin must describe the same live destination after migration. Add table tests for this adapter before deleting the old constructors.
- [ ] Update server-side SMB endpoint validation and unknown-SFTP-host-key handling to use `offsite.ParseSMBEndpoint` and `offsite.UnknownHostKeyError`.
- [ ] Run the full KyRecovery suite, its race tests, and the opt-in SMB integration test. Then perform one operator-observed live sync from the dashboard to an existing target and verify the remote bytes/hash before merging.

## Task 10: Adopt from KyNotes, then KyPost

**Repositories:** `kynotes-server`, then `kypost-server`, each in its own PR and hand-off folder.

Steps:

- [ ] In KyNotes Plan C, replace the transport-client task with the tagged `offsite` dependency. Keep blob inventory, replica state, retry scheduling, reconciliation, and audit in KyNotes.
- [ ] Exercise at least local plus one remote transport with attachment content larger than the capsule member limit; prove restore distinguishes missing (`os.ErrNotExist`) from unavailable.
- [ ] Open a separate KyPost design/plan for mail-body mirroring. Reuse only `Target`; do not move mail selection, retention, or sync state into this library.

## Final verification checklist

- [ ] Root `go.mod` and `go.sum` contain no SFTP or SMB dependency.
- [ ] Root dependency tests still discover ordinary new packages and intentionally skip `offsite/` as a nested module.
- [ ] Nested build, vet, race tests, formatting, and vulnerability scan pass.
- [ ] SFTP cannot connect without a verified host pin and never sends PEM material as a password.
- [ ] SMB requires signing, never negotiates SMB1, and rejects guest/null flags on both intermediate and final SESSION_SETUP responses; the malicious final-response downgrade test passes.
- [ ] Every target rejects unsafe names and maps only a genuinely absent object to `os.ErrNotExist`.
- [ ] `Key` is stable and credential-free.
- [ ] KyRecovery's stored targets migrate without database changes and complete a real sync.
- [ ] Tag is `offsite/v0.1.0`, distinct from root-module tags.

## Commit sequence

1. `offsite: establish nested module boundary`
2. `offsite: parse targets and protect replica paths`
3. `offsite: add local target`
4. `offsite: add S3 target`
5. `offsite: add pinned SFTP target`
6. `offsite: add signed SMB target`
7. `offsite: enforce transport contract`
8. `ci: test and scan offsite module`
9. `docs: document offsite module and release tags`

Consumer migrations are separate repositories and separate commits/PRs; do not mix them into the library PR.
