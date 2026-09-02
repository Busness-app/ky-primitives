package auditchain

import (
	"crypto/hmac"
	"fmt"
)

// VerifyRecord reports whether a record carries its own digest under this key.
//
// It says nothing about where the record sits. Resume answers a different question — is
// this the tail — and answering it requires the anchor, because every record in a healthy
// chain carries a valid digest. Callers converting a log from an older format want this
// one: they are asking whether a record is already in the shared shape, not whether it is
// the end.
func VerifyRecord(key []byte, r Record) error {
	if len(key) < minKeyBytes {
		return fmt.Errorf("%w, got %d", ErrWeakKey, len(key))
	}
	if !validHash(r.Hash) || !validHash(r.Prev) {
		return fmt.Errorf("%w: record %d carries a hash that is not 64 lowercase hex characters", ErrBrokenChain, r.Seq)
	}
	// Append starts at one, so no record legitimately carries sequence 0.
	if r.Seq == 0 {
		return fmt.Errorf("%w: record carries sequence 0, which no append mints", ErrBrokenChain)
	}
	if !hmac.Equal([]byte(digest(key, r.Seq, r.Prev, r.Fields)), []byte(r.Hash)) {
		return fmt.Errorf("%w: record %d does not carry its own digest", ErrBrokenChain, r.Seq)
	}
	return nil
}
