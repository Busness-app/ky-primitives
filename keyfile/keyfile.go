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
	"io"
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
	// ErrUnsafe reports a key path that is not a regular file owned by this process's user.
	ErrUnsafe = errors.New("keyfile: key path is not a regular file owned by the current user")
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
	f, fi, err := openKey(path)
	if err != nil {
		return err
	}
	f.Close()
	return checkKeyInfo(fi)
}

func checkKeyInfo(fi os.FileInfo) error {
	if !fi.Mode().IsRegular() || !ownedByCurrentUser(fi) {
		return fmt.Errorf("%w: %s", ErrUnsafe, fi.Name())
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: mode is %04o, want 0600", ErrPermissive, perm)
	}
	return nil
}

func read(path string, size int) ([]byte, error) {
	f, fi, err := openKey(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := checkKeyInfo(fi); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(f)
	if err != nil {
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

// openKey rejects symlinks and verifies that the file opened is the same object inspected,
// closing the pathname swap between validation and use.
func openKey(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("keyfile: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%w: %s is a symlink", ErrUnsafe, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("keyfile: %w", err)
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		f.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("keyfile: %w", err)
		}
		return nil, nil, fmt.Errorf("%w: %s changed while opening", ErrUnsafe, path)
	}
	return f, after, nil
}

// writeAll is indirected so the failed-write test can produce a real short write.
var writeAll = func(f *os.File, s string) error {
	_, err := f.WriteString(s)
	return err
}

// create writes a fresh key, failing if the path already exists.
//
// The key is written to a uniquely named temporary file in the same directory, fsynced,
// and only then linked to its final name. Writing straight to the final name meant a
// short write or a full disk left partial hex at the real path — and because this package
// refuses to replace an unreadable key, that partial file is permanent until someone
// deletes it by hand.
func create(path string, size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := randRead(key); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keyfile-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	tmpName := tmp.Name()
	// Removed on every failure path below; a no-op once the rename has consumed it.
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	// CreateTemp makes the file 0600 already; set it explicitly so the guarantee does not
	// depend on that staying true.
	if err := tmp.Chmod(0600); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	if err := writeAll(tmp, hex.EncodeToString(key)); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	// Without the fsync a crash here leaves a zero-length file that the next boot reads
	// as a corrupt key, which is the failure the refusal above then reports forever.
	if err := tmp.Sync(); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}

	// os.Link rather than os.Rename: rename would silently replace a key another process
	// created while we were writing, and this package must never destroy a key.
	if err := os.Link(tmpName, path); err != nil {
		return nil, err
	}
	// And without syncing the directory the name can be lost even though its contents
	// were durable.
	if err := syncDir(dir); err != nil {
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
