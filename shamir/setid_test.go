package shamir

import (
	"strings"
	"testing"
)

// Combine enforced the declared threshold only when it was above zero, which split the
// API in two without saying so: a share that came through ParseShare was checked, and a
// share a caller built — or a deserialiser filled in from JSON — was not. Zero is exactly
// what an absent field decodes to, so the unchecked mode was the default one, and a caller
// reading the Threshold field could reasonably believe it had been enforced.
func TestCombineRefusesSharesWithoutAUsableThreshold(t *testing.T) {
	for name, threshold := range map[string]int{
		"absent":   0,
		"one":      1,
		"negative": -1,
		"past 255": 256,
	} {
		t.Run(name, func(t *testing.T) {
			shares, err := Split([]byte("a secret worth splitting up ok!!"), 2, 3)
			if err != nil {
				t.Fatal(err)
			}
			for i := range shares {
				shares[i].Threshold = threshold
			}
			if _, err := Combine(shares); err == nil {
				t.Fatalf("combined shares declaring threshold %d", threshold)
			}
		})
	}
}

// The honest threshold still has to work, or the test above passes for a Combine that
// refuses everything.
func TestCombineStillAcceptsADeclaredThreshold(t *testing.T) {
	secret := []byte("a secret worth splitting up ok!!")
	shares, err := Split(secret, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine(shares[:2])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatal("reconstructed the wrong secret")
	}
}

// The set identifier exists to stop shares of two different splits combining into a
// plausible wrong secret. At 32 bits two splits collide with even odds after about 65,000
// of them, which a long-lived deployment issuing recovery kits reaches — and a collision
// means the one check standing between a custodian and a silently wrong secret is not
// there. 128 bits puts it out of reach.
func TestSetIDIsWideEnoughToSurviveManySplits(t *testing.T) {
	shares, err := Split([]byte("a secret worth splitting up ok!!"), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares[0].SetID) < 16 {
		t.Fatalf("set identifier is %d bytes; a birthday collision needs only 2^%d splits",
			len(shares[0].SetID), 4*len(shares[0].SetID))
	}
	if shares[0].SetID == ([16]byte{}) {
		t.Fatal("set identifier is zero, so two secrets would look like one set")
	}
	if !strings.HasPrefix(shares[0].String(), Version+"-") {
		t.Fatalf("Split emits %q, want the %s wire format", shares[0].String(), Version)
	}
}

// The 32-bit format is not parsed. Nothing outside this package ever wrote a share, so
// there are no cards to strand — and a narrow identifier accepted "for compatibility" is
// the collision the widening was for, still reachable.
func TestParseShareRejectsTheNarrowSetID(t *testing.T) {
	if _, err := ParseShare("ky1-2-a1b2c3d4-2-a1b2-0eec"); err == nil {
		t.Fatal("a 32-bit set id parsed")
	}
	// Right tag, wrong id width.
	if _, err := ParseShare("ky2-2-a1b2c3d4-2-a1b2-0eec"); err == nil {
		t.Fatal("a ky2 share carrying a 32-bit set id parsed")
	}
}
