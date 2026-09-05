package recoveryclient

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Sealer protects one settings value at rest under the product's deployment key. A product
// with an AEAD of its own wraps it (kysignon does, so its stored token keeps opening); one
// without uses NewAESGCMSealer.
type Sealer interface {
	Seal(plain []byte) (string, error)
	Open(sealed string) ([]byte, error)
}

type aesGCMSealer struct{ aead cipher.AEAD }

// NewAESGCMSealer derives a per-label AES-256-GCM key from the deployment key with
// HKDF-SHA256, so a value sealed for one setting will not open as another. key must be at
// least 32 bytes; label names the setting, for example "myapp:setting:kyrecovery_token".
func NewAESGCMSealer(key []byte, label string) (Sealer, error) {
	if len(key) < 32 {
		return nil, errors.New("recoveryclient: deployment key must be at least 32 bytes")
	}
	if label == "" {
		return nil, errors.New("recoveryclient: sealer label must not be empty")
	}
	sub, err := hkdf.Key(sha256.New, key, nil, label, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &aesGCMSealer{aead: aead}, nil
}

func (s *aesGCMSealer) Seal(plain []byte) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plain, nil)), nil
}

func (s *aesGCMSealer) Open(sealed string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("recoveryclient: sealed value is not base64: %w", err)
	}
	n := s.aead.NonceSize()
	if len(raw) < n {
		return nil, errors.New("recoveryclient: sealed value too short")
	}
	return s.aead.Open(nil, raw[:n], raw[n:], nil)
}
