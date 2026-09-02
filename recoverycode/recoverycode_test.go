package recoverycode

import (
	"strings"
	"testing"
)

func TestGenerateShape(t *testing.T) {
	codes, err := Generate(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("got %d codes", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate code %q", c)
		}
		seen[c] = true
		groups := strings.Split(c, "-")
		if len(groups) != 3 {
			t.Fatalf("code %q is not three groups", c)
		}
		for _, g := range groups {
			if len(g) != 4 {
				t.Fatalf("code %q has a group of %d characters", c, len(g))
			}
		}
		for _, r := range strings.ReplaceAll(c, "-", "") {
			if !strings.ContainsRune(Alphabet, r) {
				t.Fatalf("code %q contains %q, outside the alphabet", c, r)
			}
		}
	}
}

// ky_server_base, gridlock-server and kysignon-server issue 8 characters over a 32-symbol
// alphabet: 40 bits, stored as a bare SHA-256, guarding every other factor on the account.
// That is searchable offline. 12 characters is 60.
func TestCodesCarrySixtyBits(t *testing.T) {
	if len(Alphabet) != 32 {
		t.Fatalf("alphabet is %d symbols; a byte modulo it would be biased", len(Alphabet))
	}
	codes, err := Generate(1)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.ReplaceAll(codes[0], "-", "")); n != 12 {
		t.Fatalf("code carries %d symbols (%d bits), want 12 (60 bits)", n, n*5)
	}
}

func TestNormalize(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"abcd-efgh-ijkl", "abcdefghijkl"},
		{"ABCD-EFGH-IJKL", "abcdefghijkl"},
		{"  abcd efgh ijkl  ", "abcdefghijkl"},
		{"abcdefghijkl", "abcdefghijkl"},
		{"a-b c-d", "abcd"},
	} {
		if got := Normalize(tc.in); got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGeneratedCodesNormalizeToThemselves(t *testing.T) {
	codes, err := Generate(5)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range codes {
		if got := Normalize(c); got != strings.ReplaceAll(c, "-", "") {
			t.Fatalf("Normalize(%q) = %q", c, got)
		}
	}
}

// The redeem loop in ky_server_base breaks on the first match, so its timing reveals the
// position of the matching code in the list. Match scans every entry.
func TestMatchFindsTheRightIndex(t *testing.T) {
	hashes := []string{"aa", "bb", "cc", "dd"}
	for want, h := range hashes {
		got, ok := MatchDigest(h, hashes)
		if !ok {
			t.Fatalf("%q not found", h)
		}
		if got != want {
			t.Fatalf("%q found at %d, want %d", h, got, want)
		}
	}
}

func TestMatchReportsAbsence(t *testing.T) {
	if _, ok := MatchDigest("zz", []string{"aa", "bb"}); ok {
		t.Fatal("a hash that is not present was found")
	}
	if _, ok := MatchDigest("aa", nil); ok {
		t.Fatal("a hash was found in an empty list")
	}
	if _, ok := MatchDigest("", []string{"aa"}); ok {
		t.Fatal("an empty candidate matched")
	}
}

// An already-redeemed slot is blanked rather than removed, so indices stay stable and two
// concurrent redemptions cannot renumber each other's target.
func TestMatchSkipsRedeemedSlots(t *testing.T) {
	if _, ok := MatchDigest("", []string{"", "aa"}); ok {
		t.Fatal("an empty stored slot matched an empty candidate")
	}
	got, ok := MatchDigest("aa", []string{"", "aa"})
	if !ok || got != 1 {
		t.Fatalf("got %d ok=%v, want 1 true", got, ok)
	}
}

func TestGenerateRejectsASillyCount(t *testing.T) {
	for _, n := range []int{0, -1, 1001} {
		if _, err := Generate(n); err == nil {
			t.Errorf("count %d was accepted", n)
		}
	}
}
