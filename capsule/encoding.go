package capsule

import (
	"encoding/base64"
	"fmt"
)

// DecodeCiphertext reads the ciphertext field of a kycap/2 container.
//
// Standard base64 only. Decoding used to accept raw-url as well, because ky_server_base
// and gridlock-server encoded that way — in capsules neither of them ever persisted. With
// those containers retired there is one writer and one alphabet, and a second accepted
// spelling is a second thing that has to stay true.
func DecodeCiphertext(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("capsule ciphertext is not standard base64: %w", err)
	}
	return b, nil
}

// EncodeCiphertext writes the ciphertext field.
func EncodeCiphertext(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
