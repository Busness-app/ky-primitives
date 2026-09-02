package capsule

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// KycapFileFormat identifies the one container this package reads and writes.
//
// It is kycap/2. Two containers came before it and both are gone: kysignon-server's
// kycap/1 and kyrecovery-server's tar of manifest.json, nonce.bin and payload.enc. Each
// authenticated its ciphertext and left the manifest outside the AEAD — kycap/1 entirely,
// the tar container everything but its own aad string — so capsule_id, service_name,
// threshold, total_shares and the verification recipe could all be rewritten by someone
// who never learned the key. A 2-of-3 kit could be restated as 1-of-1 and still open.
//
// Reading them was retired rather than kept, because neither server needs its old capsules
// read and a reader that half-trusts a manifest cannot tell a caller which half.
const KycapFileFormat = "kycap/2"

// maxManifestBytes bounds the manifest before it is parsed. A manifest is a few hundred
// bytes of JSON; a megabyte of it is already absurd.
const maxManifestBytes = 1 << 20

// manifest is the capsule's description of itself. Every field of it is authenticated.
type manifest struct {
	CapsuleID   string    `json:"capsule_id"`
	ServiceName string    `json:"service_name"`
	AppVersion  string    `json:"app_version"`
	CreatedAt   time.Time `json:"created_at"`
	PayloadHash string    `json:"payload_hash"`
	Threshold   int       `json:"threshold"`
	TotalShares int       `json:"total_shares"`

	Dependencies       any `json:"dependencies,omitempty"`
	VerificationRecipe any `json:"verification_recipe,omitempty"`
}

// kycapFile is the JSON container.
//
// Manifest is kept as raw bytes rather than a decoded struct because those exact bytes are
// the additional authenticated data. Re-encoding a decoded manifest to rebuild the AAD
// would have to reproduce the writer's spelling byte for byte — field order, number
// formatting, the interface{} shape of dependencies — and any drift there fails every
// capsule rather than any forgery. The bytes that were read are the bytes that are
// authenticated.
type kycapFile struct {
	Format     string          `json:"format"`
	Manifest   json.RawMessage `json:"manifest"`
	Ciphertext string          `json:"ciphertext"`
}

// decryptPayload parses the container, decrypts it under the manifest, and returns the
// hash-verified gzipped tar payload.
func decryptPayload(raw, key []byte) ([]byte, error) {
	if len(bytes.TrimLeft(raw, " \t\r\n")) == 0 {
		return nil, ErrUnknownContainer
	}

	var cf kycapFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		return nil, fmt.Errorf("%w: not readable as %s: %v", ErrUnknownContainer, KycapFileFormat, err)
	}
	if cf.Format != KycapFileFormat {
		return nil, fmt.Errorf("%w: unsupported capsule format %q", ErrUnknownContainer, cf.Format)
	}
	if cf.Ciphertext == "" {
		return nil, fmt.Errorf("%w: container carries no ciphertext", ErrCorruptCapsule)
	}
	if len(cf.Manifest) > maxManifestBytes {
		return nil, fmt.Errorf("%w: manifest is %d bytes", ErrCorruptCapsule, len(cf.Manifest))
	}
	var m manifest
	if err := json.Unmarshal(cf.Manifest, &m); err != nil {
		return nil, fmt.Errorf("%w: unreadable manifest: %v", ErrCorruptCapsule, err)
	}

	sealed, err := DecodeCiphertext(cf.Ciphertext)
	if err != nil {
		return nil, err
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("%w: ciphertext shorter than its nonce", ErrCorruptCapsule)
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]

	// The manifest is the additional authenticated data, so any edit to it fails here
	// rather than being handed to the caller as fact.
	payload, err := gcm.Open(nil, nonce, ct, cf.Manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt capsule: %w", err)
	}
	return payload, verifyPayloadHash(payload, m.PayloadHash)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be exactly 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// verifyPayloadHash is the last line of defence when a wrong-but-valid key or a corrupt
// share reconstructs plaintext that decrypts without an AEAD error. It is load-bearing.
func verifyPayloadHash(payload []byte, want string) error {
	if want == "" {
		return fmt.Errorf("%w: manifest declares no payload hash", ErrCorruptCapsule)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != want {
		return ErrCorruptCapsule
	}
	return nil
}
