package capsule

import (
	"os"
	"testing"
)

// Open is the one function in this module that parses bytes an attacker chooses in full:
// a capsule arrives from a backup store, and both containers are walked before anything
// authenticates. It must fail, never panic, on any input at all.
func FuzzOpenNeverPanics(f *testing.F) {
	for _, p := range []string{"../testdata/capsules/kysignon.kycap", "../testdata/capsules/kyrecovery.kycap"} {
		if raw, err := os.ReadFile(p); err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte(`{"format":"kycap/2","manifest":{},"ciphertext":"AAAA"}`))
	f.Add([]byte(`{"format":"kycap/1","manifest":{"payload_hash":"00"},"ciphertext":""}`))
	f.Add([]byte("ustar\x00"))
	f.Add([]byte{})

	key := make([]byte, 32)
	f.Fuzz(func(t *testing.T, raw []byte) {
		// No target directory: this is about the parser, and writing to disk under fuzz
		// would measure the filesystem instead.
		_, _ = Open(raw, key, "")
	})
}
