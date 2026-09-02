package shamir

import (
	"bytes"
	"errors"
	"testing"
)

const secret = "MASTER-KEY-0123456789abcdef01234"

// pick returns the shares at the given 1-based indices.
func pick(t *testing.T, shares []Share, want ...byte) []Share {
	t.Helper()
	var out []Share
	for _, idx := range want {
		for _, s := range shares {
			if s.Index == idx {
				out = append(out, s)
			}
		}
	}
	if len(out) != len(want) {
		t.Fatalf("wanted indices %v, found %d shares", want, len(out))
	}
	return out
}

// TestRoundTripEveryIndexSubset is the test the suite's implementations never had. A
// share set combines correctly for every subset, not just the consecutive one that makes
// every Lagrange coefficient 1 and hides a wrong field.
func TestRoundTripEveryIndexSubset(t *testing.T) {
	shares, err := Split([]byte(secret), 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	subsets := [][]byte{
		{1, 2, 3}, {1, 2, 4}, {1, 3, 5}, {2, 3, 4}, {3, 4, 5},
		{1, 4, 5}, {2, 4, 5}, {1, 2, 5}, {1, 3, 4}, {2, 3, 5},
	}
	for _, sub := range subsets {
		got, err := Combine(pick(t, shares, sub...))
		if err != nil {
			t.Errorf("indices %v: %v", sub, err)
			continue
		}
		if !bytes.Equal(got, []byte(secret)) {
			t.Errorf("indices %v: got %q, want %q", sub, got, secret)
		}
	}
}

func TestCombineAcceptsMoreSharesThanThreshold(t *testing.T) {
	shares, err := Split([]byte(secret), 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine(shares)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(secret)) {
		t.Fatalf("got %q, want %q", got, secret)
	}
}

func TestSplitRejectsBadParameters(t *testing.T) {
	for _, tc := range []struct {
		name             string
		secret           string
		threshold, total int
	}{
		{"threshold below two", secret, 1, 5},
		{"threshold above total", secret, 6, 5},
		{"total above 255", secret, 2, 256},
		{"empty secret", "", 2, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Split([]byte(tc.secret), tc.threshold, tc.total); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

// The three 0x11d implementations panic here. A custodian retrying a shard mid-disaster
// must get an error, never a stack trace.
func TestCombineRejectsDuplicateIndex(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Combine([]Share{shares[0], shares[0]})
	if !errors.Is(err, ErrDuplicateIndex) {
		t.Fatalf("got %v, want ErrDuplicateIndex", err)
	}
}

func TestCombineRejectsMismatchedLengths(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	short := Share{Index: shares[1].Index, Value: shares[1].Value[:4]}
	_, err = Combine([]Share{shares[0], short})
	if !errors.Is(err, ErrShareLength) {
		t.Fatalf("got %v, want ErrShareLength", err)
	}
}

// Index 0 is where the secret itself sits. The 0x11d implementations accept it and
// return an all-zero secret with a nil error.
func TestCombineRejectsZeroIndex(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Combine([]Share{{Index: 0, Value: make([]byte, len(secret))}, shares[0]})
	if !errors.Is(err, ErrShareIndex) {
		t.Fatalf("got %v, want ErrShareIndex", err)
	}
}

func TestCombineRejectsTooFewShares(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Combine(shares[:1]); !errors.Is(err, ErrNotEnoughShares) {
		t.Fatalf("got %v, want ErrNotEnoughShares", err)
	}
	if _, err := Combine(nil); !errors.Is(err, ErrNotEnoughShares) {
		t.Fatalf("got %v, want ErrNotEnoughShares", err)
	}
}

func TestSplitNeverEmitsShareBelowThreshold(t *testing.T) {
	// A zero leading coefficient drops the polynomial's degree, so fewer shares than
	// promised recover the secret. Over this many splits an unguarded implementation
	// emits one with near-certainty.
	for i := 0; i < 5000; i++ {
		shares, err := Split([]byte{0x42}, 2, 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range shares {
			if bytes.Equal(s.Value, []byte{0x42}) {
				t.Fatalf("split %d: share %d equals the secret byte", i, s.Index)
			}
		}
	}
}

func TestShareStringRoundTrip(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range shares {
		got, err := ParseShare(want.String())
		if err != nil {
			t.Fatalf("%q: %v", want.String(), err)
		}
		if got.Index != want.Index || !bytes.Equal(got.Value, want.Value) {
			t.Fatalf("round trip changed share %d", want.Index)
		}
	}
}

func TestParseShareRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"", "1", "1-", "-ff", "0-ffff", "zz-ffff", "1-fff", "1-zzzz", "256-ffff", "1-ffff-2",
	} {
		if _, err := ParseShare(in); err == nil {
			t.Errorf("ParseShare(%q) = nil error, want one", in)
		}
	}
}

func TestParseShareAcceptsUppercaseAndSpace(t *testing.T) {
	got, err := ParseShare("  2-A1B2  ")
	if err != nil {
		t.Fatal(err)
	}
	if got.Index != 2 || !bytes.Equal(got.Value, []byte{0xa1, 0xb2}) {
		t.Fatalf("got %+v", got)
	}
}

// Split must not hand back aliased buffers; a caller zeroing one share must not blank
// the others.
func TestSplitSharesDoNotAlias(t *testing.T) {
	shares, err := Split([]byte(secret), 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := range shares[0].Value {
		shares[0].Value[i] = 0
	}
	if bytes.Equal(shares[1].Value, shares[2].Value) {
		t.Fatal("shares alias one another")
	}
}

func TestGoldenVectors(t *testing.T) {
	// Derived by hand, not read off this implementation. f(x) = 0x01 + 0xb2*x over
	// GF(2^8) mod 0x11b:
	//   f(1) = 0x01 ^ 0xb2                  = 0xb3
	//   f(2) = 0x01 ^ (0xb2*2 = 0x7f)       = 0x7e
	//   f(3) = 0x01 ^ (0x7f ^ 0xb2 = 0xcd)  = 0xcc
	// Pins the reduction polynomial. Change the field and this fails, which is the
	// point: every custodian card already printed would become unreadable.
	full := []Share{
		{Index: 1, Value: []byte{0xb3}},
		{Index: 2, Value: []byte{0x7e}},
		{Index: 3, Value: []byte{0xcc}},
	}
	for _, sub := range [][]int{{0, 1}, {0, 2}, {1, 2}, {0, 1, 2}} {
		var shares []Share
		for _, i := range sub {
			shares = append(shares, full[i])
		}
		got, err := Combine(shares)
		if err != nil {
			t.Fatalf("%v: %v", sub, err)
		}
		if want := []byte{0x01}; !bytes.Equal(got, want) {
			t.Fatalf("%v: got %x, want %x", sub, got, want)
		}
	}
}
