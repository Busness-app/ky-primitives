package capsule

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// The suite wrote capsules in two base64 alphabets. Both must decode forever.
func TestDecodeCiphertextAcceptsBothEncodings(t *testing.T) {
	// Chosen so the raw bytes encode to a string containing characters that differ
	// between the alphabets: 0xFB 0xFF -> "+/" standard, "-_" raw-url.
	raw := []byte{0xFB, 0xFF, 0x00, 0x11, 0x22}

	std := base64.StdEncoding.EncodeToString(raw)
	url := base64.RawURLEncoding.EncodeToString(raw)
	if std == url {
		t.Fatal("test input does not distinguish the alphabets; pick different bytes")
	}

	for name, encoded := range map[string]string{"std": std, "rawurl": url} {
		got, err := DecodeCiphertext(encoded)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("%s: got %x want %x", name, got, raw)
		}
	}
}

func TestDecodeCiphertextRejectsGarbage(t *testing.T) {
	if _, err := DecodeCiphertext("not valid base64 !!!"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestEncodeCiphertextIsStandard(t *testing.T) {
	raw := []byte{0xFB, 0xFF, 0x00}
	if got, want := EncodeCiphertext(raw), base64.StdEncoding.EncodeToString(raw); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// Trying standard before raw-url is only safe if no string decodes as both to different
// bytes. Exhaustive over every length class, which is where padding rules differ.
func TestDecodeCiphertextIsUnambiguous(t *testing.T) {
	for n := 1; n <= 64; n++ {
		raw := make([]byte, n)
		for i := range raw {
			raw[i] = byte(i * 7)
		}
		url := base64.RawURLEncoding.EncodeToString(raw)
		got, err := DecodeCiphertext(url)
		if err != nil {
			t.Fatalf("len %d: raw-url string failed to decode: %v", n, err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("len %d: raw-url string decoded as standard to different bytes: got %x want %x", n, got, raw)
		}
	}
}
