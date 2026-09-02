package capsule_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
)

// A capsule this package wrote, committed, and opened on every run. If it stops opening, a
// backup already on disk has stopped opening.
//
// It replaces the kycap/1 and tar fixtures, which were real output from kysignon-server
// and kyrecovery-server. Those containers are gone: both authenticated their ciphertext
// and left the manifest forgeable, and neither server needs its old capsules read. What
// the fixture is for did not change — a golden capsule whose key is withheld cannot prove
// anything, which is why the key is committed beside it.
func TestOpensEveryPersistedCapsule(t *testing.T) {
	paths := fixturePaths(t)

	for _, p := range paths {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, key := loadFixture(t, p)

			files, err := capsule.Open(raw, key, filepath.Join(t.TempDir(), "restore"))
			if err != nil {
				t.Fatalf("a capsule written by an earlier version of this package failed to open: %v", err)
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
	for _, p := range fixturePaths(t) {
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
	for _, p := range fixturePaths(t) {
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, key := loadFixture(t, p)
			raw[len(raw)/2] ^= 0xFF

			if _, err := capsule.Open(raw, key, ""); err == nil {
				t.Fatal("a tampered capsule opened cleanly")
			}
		})
	}
}

// The containers this package used to read are now refused rather than half-trusted. A
// kycap/1 capsule's manifest was forgeable by anyone who could reach the file, so opening
// one and handing back its files told the caller nothing about whether the manifest
// describing them was real.
func TestOpenRejectsRetiredContainers(t *testing.T) {
	for name, raw := range map[string][]byte{
		"kycap/1": []byte(`{"format":"kycap/1","manifest":{"payload_hash":"00"},"ciphertext":"AAAAAAAAAAAAAAAAAAAAAA=="}`),
		"tar":     append([]byte("manifest.json\x00"), make([]byte, 1024)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := capsule.Open(raw, make([]byte, 32), ""); err == nil {
				t.Fatalf("a retired %s container opened", name)
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

func fixturePaths(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("../testdata/capsules/*.kycap")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no capsule fixture on disk, so nothing here proves a capsule still opens")
	}
	return paths
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
