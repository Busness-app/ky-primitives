package capsule

import (
	"os"
	"testing"
)

// Open is the one function in this module that parses bytes an attacker chooses in full:
// a capsule arrives from a backup store, and the container is parsed before anything
// authenticates. It must fail, never panic, on any input at all.
func FuzzOpenNeverPanics(f *testing.F) {
	if raw, err := os.ReadFile("../testdata/capsules/kycap2.kycap"); err == nil {
		f.Add(raw)
	}
	f.Add([]byte(`{"format":"kycap/2","manifest":{},"ciphertext":"AAAA"}`))
	f.Add([]byte(`{"format":"kycap/2","manifest":{"payload_hash":"00"},"ciphertext":""}`))
	f.Add([]byte(`{"format":"kycap/1","manifest":{},"ciphertext":"AAAA"}`))
	f.Add([]byte{})

	key := make([]byte, 32)
	f.Fuzz(func(t *testing.T, raw []byte) {
		// No target directory: this is about the parser, and writing to disk under fuzz
		// would measure the filesystem instead.
		_, _, _ = Open(raw, key, "")
	})
}
