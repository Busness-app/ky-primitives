package auditchain

import (
	"errors"
	"testing"
)

// These two isolate checks that TestVerifyRecordRefusesSequenceZero and
// TestVerifyRecordRefusesAMalformedHash (verify_record_test.go, external package) do not:
// both of those fixtures carry a garbage Hash, so the generic "does not carry its own
// digest" comparison refuses the record whether or not the specific check under test
// exists. A fixture has to carry the correct digest for its own malformed content, or the
// digest comparison masks everything else.

// Only the explicit Seq == 0 check can refuse this: the digest is genuine.
func TestVerifyRecordRefusesSequenceZeroEvenWithACorrectDigest(t *testing.T) {
	key := testKey()
	fields := []string{"a"}
	rec := Record{Seq: 0, Prev: genesis, Fields: fields}
	rec.Hash = digest(key, rec.Seq, rec.Prev, rec.Fields)

	if err := VerifyRecord(key, rec); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("got %v, want ErrBrokenChain for sequence 0 carrying a correct digest", err)
	}
}

// Prev is an input to the digest, so a Prev of the wrong shape can still have a genuine
// digest computed over it — unlike a malformed Hash, which can never equal any digest and
// so can never isolate validHash(r.Hash) from the digest comparison that follows it. Only
// validHash(r.Prev) can refuse this one.
func TestVerifyRecordRefusesAMalformedPrevEvenWithACorrectDigest(t *testing.T) {
	key := testKey()
	fields := []string{"a"}
	badPrev := "not-64-lowercase-hex-characters"
	rec := Record{Seq: 1, Prev: badPrev, Fields: fields}
	rec.Hash = digest(key, rec.Seq, rec.Prev, rec.Fields)

	if err := VerifyRecord(key, rec); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("got %v, want ErrBrokenChain for a malformed Prev carrying a correct digest", err)
	}
}
