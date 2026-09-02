package capsule

import (
	"testing"
)

// Open holds the raw container, the decrypted payload and every expanded member in memory
// at once. A per-member ceiling of 4 GiB and a total of 8 GiB therefore did not bound a
// hostile capsule to something a server survives — it bounded it to several times the
// memory of the machine, and the process dies before the friendly error is returned.
//
// These are policy numbers, so the test is a policy test: it exists so that raising them
// back into gigabyte territory has to be done on purpose, in a diff that says so.
func TestExtractionBudgetsFitAServer(t *testing.T) {
	const ceiling = int64(512 << 20)

	if maxCapsuleExpandedTotal > ceiling {
		t.Errorf("total expansion budget is %d bytes; a server cannot hold that", maxCapsuleExpandedTotal)
	}
	if maxCapsuleFileBytes > maxCapsuleExpandedTotal {
		t.Errorf("a single member may be %d bytes but the whole archive only %d", maxCapsuleFileBytes, maxCapsuleExpandedTotal)
	}
}
