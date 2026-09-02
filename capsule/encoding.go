package capsule

import (
	"encoding/base64"
	"fmt"
)

// DecodeCiphertext reads the ciphertext field of a kycap/1 container.
//
// The suite wrote two base64 alphabets: kysignon-server used base64.StdEncoding and is
// the only one whose output ever reached a disk, while ky_server_base and
// gridlock-server used base64.RawURLEncoding in capsules they never persisted. Accepting
// both costs four lines and removes a whole class of surprise when those two converge.
//
// Trying standard first is unambiguous rather than a guess: standard requires padding to
// a multiple of four and rejects the '-' and '_' that raw-url uses, so a raw-url string
// either fails here and falls through, or contains only characters both alphabets agree
// on and decodes identically either way.
func DecodeCiphertext(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("capsule ciphertext is neither standard nor raw-url base64: %w", err)
	}
	return b, nil
}

// EncodeCiphertext writes new capsules in one alphabet. Reading stays permissive;
// writing converges on standard base64.
func EncodeCiphertext(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
