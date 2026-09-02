// Package capsule reads and writes the suite's encrypted backup containers.
//
// Two containers exist on disk and hold real recovery data:
//
//	kycap/1  a JSON object with a base64 ciphertext string, written by kysignon-server
//	tar      a tar of manifest.json, nonce.bin and payload.enc, written by kyrecovery-server
//
// Open reads both. Seal writes kycap/1 only. Reading must stay permissive forever —
// dropping either container orphans backups already on disk — while writing converges so
// the suite stops accumulating formats.
//
// Both containers decrypt to the same thing: a gzipped tar of the backed-up files. That
// is why the hardened extraction in extract.go is shared, and why a kyrecovery capsule
// opened through this package gets path and size checks its own Unpack never applied.
package capsule

import (
	"errors"
	"os"
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
)

// File is one member of a capsule's payload.
type File struct {
	Path    string
	Content []byte
	Mode    os.FileMode
}

// Open parses a capsule of either container, decrypts it, verifies the payload hash, and
// returns its files. When targetDir is non-empty the files are also written there under
// the containment rules described in extract.go; the directory must be empty or absent.
//
// key is raw bytes, never a hex string. The suite's implementations disagree on that
// (ky_server_base passes hex, kysignon-server passes bytes) and bytes is the one that
// cannot be got wrong silently: a hex string of the right length is a valid 64-byte key
// that simply decrypts to garbage.
func Open(raw, key []byte, targetDir string) ([]File, error) {
	payload, err := decryptPayload(raw, key)
	if err != nil {
		return nil, err
	}
	return extractPayload(payload, targetDir)
}
