package shamir

import (
	"errors"
	"strings"
	"testing"
)

// Finding 5.1: a share carried no field identifier, so a share produced by the suite's
// old 0x11d implementation was byte-indistinguishable from one of ours and combined into
// silent garbage. It carried no threshold either, so too few shares also returned garbage
// with a nil error. Both are now refusals.

func TestShareStringIsVersionedAndSelfDescribing(t *testing.T) {
	shares, err := Split([]byte("a secret worth splitting up ok!!"), 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range shares {
		if !strings.HasPrefix(s.String(), Version+"-") {
			t.Fatalf("share %q does not begin with the version tag %q", s, Version)
		}
		if s.Threshold != 3 {
			t.Fatalf("share carries threshold %d, want 3", s.Threshold)
		}
		if s.SetID != shares[0].SetID {
			t.Fatal("shares of one secret carry different set identifiers")
		}
	}
	if shares[0].SetID == ([16]byte{}) {
		t.Fatal("set identifier is zero, so two secrets would look like one set")
	}
}

// An unversioned share is what every previous implementation in the suite produced.
func TestParseShareRejectsAnUnversionedShare(t *testing.T) {
	for _, in := range []string{"1-a1b2c3d4", "2-ffff", "ky0-3-9f2a71c4-1-aabb-1234"} {
		if _, err := ParseShare(in); !errors.Is(err, ErrShareVersion) {
			t.Errorf("ParseShare(%q) = %v, want ErrShareVersion", in, err)
		}
	}
}

func TestShareRoundTripsThroughItsString(t *testing.T) {
	shares, err := Split([]byte("another secret entirely, 32 by!!"), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range shares {
		got, err := ParseShare(want.String())
		if err != nil {
			t.Fatalf("%q: %v", want, err)
		}
		if got.String() != want.String() {
			t.Fatalf("round trip changed %q into %q", want, got)
		}
	}
}

// A transcription slip must be caught at parse time, not surface as a wrong secret.
func TestParseShareCatchesTranscriptionErrors(t *testing.T) {
	shares, err := Split([]byte("yet another secret, 32 bytes ok!"), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	good := shares[0].String()
	body := good[:strings.LastIndex(good, "-")]
	corrupt := []string{
		strings.Replace(good, "a", "b", 1),
		body + "-0000",
		strings.ToUpper(good[:3]) + good[3:],
	}
	for _, in := range corrupt {
		if in == good {
			continue
		}
		if _, err := ParseShare(in); err == nil {
			t.Errorf("ParseShare(%q) accepted a corrupted share", in)
		}
	}
}

// This is the failure the package previously documented as impossible to catch.
func TestCombineRejectsFewerSharesThanTheThreshold(t *testing.T) {
	secret := []byte("a three of five secret, 32 bytes")
	shares, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Combine(shares[:2]); !errors.Is(err, ErrNotEnoughShares) {
		t.Fatalf("got %v, want ErrNotEnoughShares", err)
	}
	got, err := Combine(shares[:3])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatal("the threshold itself did not reconstruct")
	}
}

// Shares of two different secrets combine into garbage; the set identifier makes it an
// error instead.
func TestCombineRejectsSharesFromDifferentSets(t *testing.T) {
	a, err := Split([]byte("secret number one, 32 bytes long"), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Split([]byte("secret number two, 32 bytes long"), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Combine([]Share{a[0], b[1]}); !errors.Is(err, ErrShareSet) {
		t.Fatalf("got %v, want ErrShareSet", err)
	}
}

func TestCombineRejectsMixedThresholds(t *testing.T) {
	shares, err := Split([]byte("mixed threshold secret, 32 byte!"), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	shares[1].Threshold = 3
	if _, err := Combine(shares[:2]); !errors.Is(err, ErrShareSet) {
		t.Fatalf("got %v, want ErrShareSet", err)
	}
}
