// Package capsule reads and writes the suite's encrypted backup container.
//
// The container is kycap/2: a JSON object holding the manifest, a base64 ciphertext with
// the nonce prefixed, and nothing else. The manifest is bound into the AEAD, so every
// field describing the capsule is authenticated rather than merely present.
//
// Two containers came before it — kysignon-server's kycap/1 and kyrecovery-server's tar —
// and both are retired. Each authenticated its ciphertext and left the manifest outside
// the AEAD, which made the recovery topology a capsule advertises editable by anyone who
// could reach the file.
//
// The payload is a gzipped tar of the backed-up files, extracted through the hardening in
// extract.go.
package capsule

import (
	"errors"
	"os"

	"github.com/Busness-app/ky-primitives/recoverykey"
)

var (
	// ErrCorruptCapsule reports a container that parsed but failed its payload hash.
	ErrCorruptCapsule = errors.New("corrupt capsule container or failed hash validation")
	// ErrUnknownContainer reports bytes that match neither container.
	ErrUnknownContainer = errors.New("not a recognised capsule container")
	// ErrPathTraversal reports an archive member that would escape the target directory.
	ErrPathTraversal = errors.New("capsule contains a path that escapes the target directory")
	// ErrCapsuleTooLarge reports an archive that expands past the permitted budget.
	ErrCapsuleTooLarge = errors.New("capsule payload exceeds the permitted expanded size")
	// ErrCapsuleEntryType reports an archive member that is not a regular file.
	ErrCapsuleEntryType = errors.New("capsule contains an entry that is not a regular file")
	// ErrTargetNotEmpty reports a restore target that already has contents.
	ErrTargetNotEmpty = errors.New("restore target directory is not empty")
	// ErrDuplicatePath reports two members that normalise to one destination.
	ErrDuplicatePath = errors.New("capsule contains two paths that normalise to the same destination")
	// ErrWrongRecoveryKey reports a capsule sealed to a recovery key other than the one
	// Open was given. It is checked before any decapsulation, so a wrong kit fails cheaply
	// and by name.
	ErrWrongRecoveryKey = errors.New("capsule is sealed to a different recovery key")
)

// File is one member of a capsule's payload.
type File struct {
	Path    string
	Content []byte
	Mode    os.FileMode
}

// Open parses a kycap/3 container, decrypts it with the recovery private key, verifies the
// payload hash, and returns the authenticated manifest with the files. When targetDir is
// non-empty the files are also written there under the containment rules in extract.go;
// the directory must be empty or absent. When it is empty nothing is written and the files
// are returned in memory.
//
// The manifest is returned because a successful Open is the only proof it was not
// rewritten. Callers that want it without a key want ReadUnverifiedManifest, and should
// read that type's doc comment first.
//
// A capsule names the recovery key it was sealed to. Open compares that name with the key
// it was given before decapsulating anything, and fails with ErrWrongRecoveryKey on a
// mismatch — the custodians brought the wrong kit, and that is worth saying plainly.
func Open(raw []byte, with recoverykey.PrivateKey, targetDir string) (Manifest, []File, error) {
	m, payload, err := decryptPayload(raw, with)
	if err != nil {
		return Manifest{}, nil, err
	}
	// The file list is inside the payload, so it is read only after decryptPayload has
	// authenticated the container and verified the payload hash. A capsule sealed before
	// v0.3.0 carries no such member and reports no files; its payload hash still covers
	// every byte of it.
	files, entries, err := extractPayload(payload, targetDir)
	if err != nil {
		return Manifest{}, nil, err
	}
	m.Files = entries
	return Manifest{UnverifiedManifest: m}, files, nil
}
