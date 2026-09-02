package capsule_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
)

// One real capsule from each container the suite persists. If either stops opening, a
// backup already on disk has stopped opening.
func TestOpensEveryPersistedCapsule(t *testing.T) {
	paths, err := filepath.Glob("../testdata/capsules/*.kycap")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 2 {
		t.Fatalf("expected a fixture from each persisted container, found %d", len(paths))
	}

	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, key := loadFixture(t, p)

			files, err := capsule.Open(raw, key, filepath.Join(t.TempDir(), "restore"))
			if err != nil {
				t.Fatalf("capsule from a shipped implementation failed to open: %v", err)
			}
			if len(files) == 0 {
				t.Fatal("opened but produced no files")
			}
			for _, f := range files {
				t.Logf("%s: %s (%d bytes, mode %o)", filepath.Base(p), f.Path, len(f.Content), f.Mode)
			}
		})
	}
}

// A wrong key must fail loudly. AES-GCM authenticates, so this should never reach the
// payload hash — but the hash is the backstop if it ever does.
func TestOpenRejectsWrongKey(t *testing.T) {
	paths, _ := filepath.Glob("../testdata/capsules/*.kycap")
	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, key := loadFixture(t, p)
			key[0] ^= 0xFF

			if _, err := capsule.Open(raw, key, ""); err == nil {
				t.Fatal("a capsule opened with the wrong key")
			}
		})
	}
}

// Corrupting the container must not produce plaintext.
func TestOpenRejectsTamperedContainer(t *testing.T) {
	paths, _ := filepath.Glob("../testdata/capsules/*.kycap")
	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, key := loadFixture(t, p)
			raw[len(raw)/2] ^= 0xFF

			if _, err := capsule.Open(raw, key, ""); err == nil {
				t.Fatal("a tampered capsule opened cleanly")
			}
		})
	}
}

func TestOpenRejectsUnknownContainer(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":      {},
		"whitespace": []byte("   \n\t "),
		"plain text": []byte("this is not a capsule"),
		"wrong json": []byte(`{"format":"kycap/99","manifest":{},"ciphertext":"AAAA"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := capsule.Open(raw, make([]byte, 32), ""); err == nil {
				t.Fatalf("%q opened as a capsule", name)
			}
		})
	}
}

func loadFixture(t *testing.T, path string) (raw, key []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keyHex, err := os.ReadFile(strings.TrimSuffix(path, ".kycap") + ".key")
	if err != nil {
		t.Fatal(err)
	}
	key, err = hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil {
		t.Fatalf("fixture key is not hex: %v", err)
	}
	return raw, key
}
