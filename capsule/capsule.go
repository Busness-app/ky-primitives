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
