package capsule

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// One writer, one alphabet. Decoding used to try raw-url as well, for capsules
// ky_server_base and gridlock-server encoded that way and never persisted; with those
// containers retired a second accepted spelling is only a second thing that has to stay
// true. A raw-url string that is not also valid standard base64 is now a refusal.
func TestDecodeCiphertextAcceptsOnlyStandardBase64(t *testing.T) {
	// 0xFB 0xFF encodes to "+/" in standard and "-_" in raw-url, so the two disagree.
	raw := []byte{0xFB, 0xFF, 0x00, 0x11, 0x22}

	std := base64.StdEncoding.EncodeToString(raw)
	url := base64.RawURLEncoding.EncodeToString(raw)
	if std == url {
		t.Fatal("test input does not distinguish the alphabets; pick different bytes")
	}

	got, err := DecodeCiphertext(std)
	if err != nil {
		t.Fatalf("standard base64 was refused: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("got %x want %x", got, raw)
	}
	if _, err := DecodeCiphertext(url); err == nil {
		t.Fatal("a raw-url ciphertext decoded; this package writes one alphabet")
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

// Round trip over every length class, which is where padding rules differ.
func TestCiphertextRoundTrips(t *testing.T) {
	for n := 1; n <= 64; n++ {
		raw := make([]byte, n)
		for i := range raw {
			raw[i] = byte(i * 7)
		}
		got, err := DecodeCiphertext(EncodeCiphertext(raw))
		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("len %d: got %x want %x", n, got, raw)
		}
	}
}
