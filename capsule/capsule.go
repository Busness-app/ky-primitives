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

// Open parses a kycap/2 container, decrypts it, verifies the payload hash, and returns the
// authenticated manifest with the files. When targetDir is non-empty the files are also
// written there under the containment rules in extract.go; the directory must be empty or
// absent. When it is empty nothing is written and the files are returned in memory.
//
// The manifest is returned because a successful Open is the only proof it was not
// rewritten. Callers that want it without a key want ReadUnverifiedManifest, and should
// read that type's doc comment first.
//
// key is raw bytes, never a hex string. The suite's implementations disagree on that
// (ky_server_base passes hex, kysignon-server passes bytes). Passing the hex spelling of a
// 32-byte key is 64 bytes, which newGCM refuses outright, so the mistake is loud here —
// but it was silent in the implementations this replaced, which hashed or truncated
// whatever they were handed into 32 bytes and decrypted to garbage.
func Open(raw, key []byte, targetDir string) (Manifest, []File, error) {
	m, payload, err := decryptPayload(raw, key)
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
