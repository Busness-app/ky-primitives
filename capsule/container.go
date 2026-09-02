package capsule

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// KycapFileFormat identifies the JSON container this package writes.
const KycapFileFormat = "kycap/1"

// maxContainerBytes bounds the tar container walk. The container holds three small
// members; anything larger is either corrupt or hostile.
const maxContainerBytes = int64(8 << 30)

// manifest carries the fields both containers agree on. Each container has extra fields
// of its own, but only these are needed to decrypt and verify.
type manifest struct {
	CapsuleID   string    `json:"capsule_id"`
	ServiceName string    `json:"service_name"`
	AppVersion  string    `json:"app_version"`
	CreatedAt   time.Time `json:"created_at"`
	PayloadHash string    `json:"payload_hash"`
	Threshold   int       `json:"threshold"`
	TotalShares int       `json:"total_shares"`
	AAD         string    `json:"aad"`

	Dependencies       any `json:"dependencies,omitempty"`
	VerificationRecipe any `json:"verification_recipe,omitempty"`
}

// kycapFile is the kycap/1 JSON container.
type kycapFile struct {
	Format     string   `json:"format"`
	Manifest   manifest `json:"manifest"`
	Ciphertext string   `json:"ciphertext"`
}

// decryptPayload dispatches on container type and returns the decrypted, hash-verified
// gzipped tar payload.
//
// Dispatch is on the first byte, which is decisive: the JSON container always begins with
// '{', and a tar archive always begins with a member name, which cannot be '{' because
// safeRelPath-worthy names never are and a leading brace would make the header's checksum
// field land on non-numeric bytes. A wrong guess costs nothing — the chosen parser fails
// and the caller sees ErrUnknownContainer rather than a silent misread.
func decryptPayload(raw, key []byte) ([]byte, error) {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, ErrUnknownContainer
	}
	if trimmed[0] == '{' {
		return decryptKycap1(trimmed, key)
	}
	return decryptTarContainer(raw, key)
}

// decryptKycap1 reads kysignon-server's JSON container: nonce prefixed to the ciphertext,
// no additional authenticated data.
func decryptKycap1(raw, key []byte) ([]byte, error) {
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

	payload, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt capsule: %w", err)
	}
	return payload, verifyPayloadHash(payload, cf.Manifest.PayloadHash)
}

// decryptTarContainer reads kyrecovery-server's tar container: nonce in its own member,
// and the manifest's aad field bound into the AEAD.
func decryptTarContainer(raw, key []byte) ([]byte, error) {
	var manifestBytes, nonce, sealed []byte

	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnknownContainer, err)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxContainerBytes))
		if err != nil {
			return nil, err
		}
		switch hdr.Name {
		case "manifest.json":
			manifestBytes = data
		case "nonce.bin":
			nonce = data
		case "payload.enc":
			sealed = data
		}
	}

	switch {
	case len(manifestBytes) == 0:
		return nil, fmt.Errorf("%w: tar container has no manifest.json", ErrCorruptCapsule)
	case len(nonce) == 0:
		return nil, fmt.Errorf("%w: tar container has no nonce.bin", ErrCorruptCapsule)
	case len(sealed) == 0:
		return nil, fmt.Errorf("%w: tar container has no payload.enc", ErrCorruptCapsule)
	}

	var m manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("%w: unreadable manifest: %v", ErrCorruptCapsule, err)
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: nonce is %d bytes, expected %d", ErrCorruptCapsule, len(nonce), gcm.NonceSize())
	}

	payload, err := gcm.Open(nil, nonce, sealed, []byte(m.AAD))
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
