package shamir

import (
	"errors"
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
	if !strings.HasPrefix(shares[0].String(), VersionV2+"-") {
		t.Fatalf("Split emits %q, want the %s wire format", shares[0].String(), VersionV2)
	}
}

// A wider identifier is a new wire format, and the old one is on custodian cards that were
// printed and put in envelopes. Those still have to parse, or the format change is a
// recovery failure rather than a hardening.
func TestParseShareStillReadsKy1Cards(t *testing.T) {
	got, err := ParseShare("ky1-2-a1b2c3d4-2-a1b2-0eec")
	if err != nil {
		t.Fatalf("a ky1 custodian card no longer parses: %v", err)
	}
	if got.Threshold != 2 || got.Index != 2 {
		t.Fatalf("parsed %d-of-?, index %d", got.Threshold, got.Index)
	}
	want := [16]byte{12: 0xa1, 13: 0xb2, 14: 0xc3, 15: 0xd4}
	if got.SetID != want {
		t.Fatalf("ky1 set id widened to %x, want %x", got.SetID, want)
	}
}

// Two ky1 cards that disagreed in their 32 bits must still disagree once widened, or the
// compatibility path throws away the check it is preserving.
func TestWidenedKy1SetIDsStayDistinct(t *testing.T) {
	a, err := ParseShare("ky1-2-a1b2c3d4-2-a1b2-0eec")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseShare("ky1-3-9f2a71c4-1-aabb-0632")
	if err != nil {
		t.Fatal(err)
	}
	if a.SetID == b.SetID {
		t.Fatal("two different ky1 set ids widened to the same value")
	}
	if _, err := Combine([]Share{a, b}); !errors.Is(err, ErrShareSet) {
		t.Fatalf("got %v, want ErrShareSet combining across two ky1 splits", err)
	}
}
