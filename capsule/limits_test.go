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
// back into gigabyte territory has to be done on purpose, in a diff that says so. It
// asserts the constants rather than a relation between them — the earlier version checked
// only "total <= 512 MiB" and "member <= total", which both numbers could double under
// while still passing, in the file whose numbers had already drifted by 32x once.
func TestExtractionBudgetsFitAServer(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int64
		want int64
	}{
		{"maxCapsuleExpandedTotal", maxCapsuleExpandedTotal, 256 << 20},
		{"maxCapsuleFileBytes", maxCapsuleFileBytes, 64 << 20},
		{"maxContainerBytes", int64(maxContainerBytes), 384 << 20},
		{"maxCapsuleFiles", int64(maxCapsuleFiles), 4096},
	} {
		if tc.got != tc.want {
			t.Errorf("%s is %d bytes, the documented budget is %d; raising it is a policy change",
				tc.name, tc.got, tc.want)
		}
	}

	// The relation still has to hold, and it is not implied by the values above once any
	// of them is edited.
	if maxCapsuleFileBytes > maxCapsuleExpandedTotal {
		t.Errorf("a single member may be %d bytes but the whole archive only %d", maxCapsuleFileBytes, maxCapsuleExpandedTotal)
	}
}
