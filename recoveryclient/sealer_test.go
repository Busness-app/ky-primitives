package recoveryclient

import (
	"bytes"
	"testing"
)

func TestAESGCMSealerRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	s, err := NewAESGCMSealer(key, "app:setting:kyrecovery_token")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal([]byte("token-value"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.Open(sealed)
	if err != nil || string(plain) != "token-value" {
		t.Fatalf("open: %v %q", err, plain)
	}
	if _, err := s.Open(sealed[:len(sealed)-4] + "AAAA"); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
}

func TestAESGCMSealerLabelSeparates(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	a, _ := NewAESGCMSealer(key, "a")
	b, _ := NewAESGCMSealer(key, "b")
	sealed, _ := a.Seal([]byte("x"))
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("a ciphertext sealed under label a opened under label b")
	}
}

func TestAESGCMSealerRefusesShortKeyAndEmptyLabel(t *testing.T) {
	if _, err := NewAESGCMSealer(make([]byte, 16), "a"); err == nil {
		t.Fatal("16-byte deployment key accepted")
	}
	if _, err := NewAESGCMSealer(make([]byte, 32), ""); err == nil {
		t.Fatal("empty label accepted")
	}
}
