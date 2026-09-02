// Package keyfile loads a long-lived secret from disk, creating it on first use.
//
// Seven products in the suite did this seven ways, and the disagreements were not
// stylistic. kynotes-server continued past a key file it could not decode and left the
// secret an empty string, so the server ran with no pairing secret and no error.
// kypassword-server's audit store regenerated on an empty file, which silently orphans
// every record written under the old key. Five of the seven read and then wrote with no
// exclusion, so two starting processes each minted a key and one won after the other had
// already sealed data. Only one fsynced, so a crash just after first boot left a
// zero-length file for the next boot to misread.
//
// This package refuses rather than guesses: an existing file that does not decode to
// exactly the expected size is an error, never something to replace.
package keyfile

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	// ErrUnreadable reports an existing key file that does not decode to the expected
	// size. The file is left exactly as it was found.
	ErrUnreadable = errors.New("keyfile: existing key file is unreadable and will not be replaced")
	// ErrPermissive reports a key file that some account other than its owner can read.
	ErrPermissive = errors.New("keyfile: key file is readable beyond its owner")
)

// minSize is the floor for a secret worth persisting. A shorter one is a mistake in the
// caller, and a weak key is worse than a loud failure.
const minSize = 16

// mu serialises callers in this process. os.O_EXCL handles the cross-process race; this
// stops the common in-process one without paying for a lock file.
var mu sync.Mutex

// LoadOrCreate returns the size-byte secret stored at path, creating it if absent.
//
// The file holds lowercase hex: an operator can read it, copy it and diff it, and there
// is no ambiguity about whether the bytes are raw, hex or base64 — which three of the
// seven implementations disagreed about.
func LoadOrCreate(path string, size int) ([]byte, error) {
	if size < minSize {
		return nil, fmt.Errorf("keyfile: size %d is below the %d-byte floor", size, minSize)
	}

	mu.Lock()
	defer mu.Unlock()

	if key, err := read(path, size); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}

	key, err := create(path, size)
	if errors.Is(err, os.ErrExist) {
		// Another process won the race between the read above and the create. Its key is
		// the real one; ours was never written and nothing has used it.
		return read(path, size)
	}
	return key, err
}

// RequireOwnerOnly reports whether path is readable by anyone but its owner. Nothing in
// the suite checked this, so a key file relaxed to 0644 by a stray chmod or a restore
// kept being used as though it were secret.
func RequireOwnerOnly(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: mode is %04o, want 0600", ErrPermissive, perm)
	}
	return nil
}

func read(path string, size int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := RequireOwnerOnly(path); err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: not hex", ErrUnreadable, path)
	}
	if len(key) != size {
		return nil, fmt.Errorf("%w: %s holds %d bytes, expected %d", ErrUnreadable, path, len(key), size)
	}
	return key, nil
}

// create writes a fresh key, failing if the path already exists.
func create(path string, size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := randRead(key); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(hex.EncodeToString(key)); err != nil {
		f.Close()
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	// Without the fsync a crash here leaves a zero-length file that the next boot reads
	// as a corrupt key, which is the failure the refusal above then reports forever.
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	// And without syncing the directory the file's name can be lost even though its
	// contents were durable.
	if err := syncDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return key, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("keyfile: %w", err)
	}
	return nil
}

// randRead is crypto/rand.Read, named so the error is never the discarded one. Two
// implementations wrote `_, _ = rand.Read(b)` and shipped an all-zero secret on failure.
func cryptoRandRead(b []byte) (int, error) { return cryptorand.Read(b) }

var randRead = cryptoRandRead
