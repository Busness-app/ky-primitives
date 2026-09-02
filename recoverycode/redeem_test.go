package recoverycode

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// testHash stands in for whatever the product stores. This package does not own hashing —
// the products disagree about it for reasons it cannot settle — so the workflow takes the
// hash as an argument rather than picking one.
func testHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Match was named for codes and compared digests. Nothing in the signature said so: both
// parameters are strings, so passing the thing the user typed compiled, ran, and simply
// never matched. The package documented "the normalisation both sides of a comparison must
// agree on" and then left every caller to remember it.
//
// This is the shape of the failure: enrolment stores a hash over the normalised code, and
// redemption receives what the user actually typed — uppercase, with the separators the
// card prints. A caller that forgets one Normalize rejects a valid recovery code during
// the emergency the code exists for.
func TestRedemptionMatchesWhateverCaseAndSpacingTheUserTypes(t *testing.T) {
	codes, err := Generate(3)
	if err != nil {
		t.Fatal(err)
	}
	stored := make([]string, len(codes))
	for i, c := range codes {
		stored[i] = testHash(Normalize(c))
	}

	// Every spelling of the second code that a human plausibly produces off a card.
	for name, typed := range map[string]string{
		"as printed":  codes[1],
		"uppercase":   strings.ToUpper(codes[1]),
		"no hyphens":  strings.ReplaceAll(codes[1], "-", ""),
		"spaces":      strings.ReplaceAll(codes[1], "-", " "),
		"padded":      "  " + codes[1] + "  ",
		"mixed hyphs": strings.ToUpper(strings.ReplaceAll(codes[1], "-", "")),
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := MatchCode(typed, stored, testHash)
			if !ok {
				t.Fatalf("a valid recovery code typed as %q was rejected", typed)
			}
			if got != 1 {
				t.Fatalf("matched slot %d, want 1", got)
			}
		})
	}
}

// A code that was never issued must not match, or the workflow above would pass by
// matching everything.
func TestRedemptionRejectsACodeThatWasNeverIssued(t *testing.T) {
	codes, err := Generate(2)
	if err != nil {
		t.Fatal(err)
	}
	stored := []string{testHash(Normalize(codes[0])), testHash(Normalize(codes[1]))}

	if _, ok := MatchCode("aaaa-bbbb-cccc", stored, testHash); ok {
		t.Fatal("a code that was never issued matched")
	}
	if _, ok := MatchCode("", stored, testHash); ok {
		t.Fatal("an empty code matched")
	}
}

// A redeemed slot is blanked in place rather than removed, so it must never match — and
// must not be revived by a hash function that maps the empty string to something.
func TestRedemptionSkipsABlankedSlot(t *testing.T) {
	codes, err := Generate(2)
	if err != nil {
		t.Fatal(err)
	}
	stored := []string{"", testHash(Normalize(codes[1]))}

	got, ok := MatchCode(codes[1], stored, testHash)
	if !ok || got != 1 {
		t.Fatalf("MatchCode = %d, %v; want slot 1", got, ok)
	}
	if _, ok := MatchCode(codes[0], stored, testHash); ok {
		t.Fatal("a code whose slot was blanked still matched")
	}
}
