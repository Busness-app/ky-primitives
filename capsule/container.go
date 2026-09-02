package capsule

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// maxContainerBytes bounds attacker-controlled input before JSON parsing and base64
// decoding can make additional copies of it. The plaintext ceiling is 256 MiB; this leaves
// room for base64 expansion, the manifest and archive framing.
const maxContainerBytes = 384 << 20

// manifest is the authenticated description of a capsule. It is carried and authenticated
// as the exact bytes that were read, never a re-encoding of this struct — see kycapFile.
type manifest = UnverifiedManifest

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

// parseContainer parses the container envelope and bounds every attacker-controlled part of
// it before anything downstream can act on it. decryptPayload calls this with bytes it will
// decrypt under a key; ReadUnverifiedManifest calls it with bytes from a caller who has no
// key at all and so no other defence — both need the same limits, and a second copy of any
// of them is how it stops matching the first.
func parseContainer(raw []byte) (kycapFile, error) {
	if err := checkContainerSize("container", len(raw)); err != nil {
		return kycapFile{}, err
	}
	if len(bytes.TrimLeft(raw, " \t\r\n")) == 0 {
		return kycapFile{}, ErrUnknownContainer
	}

	var cf kycapFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		return kycapFile{}, fmt.Errorf("%w: not readable as %s: %v", ErrUnknownContainer, KycapFileFormat, err)
	}
	if cf.Format != KycapFileFormat {
		return kycapFile{}, fmt.Errorf("%w: unsupported capsule format %q", ErrUnknownContainer, cf.Format)
	}
	if err := checkContainerSize("encoded ciphertext", len(cf.Ciphertext)); err != nil {
		return kycapFile{}, err
	}
	if len(cf.Manifest) > maxManifestBytes {
		return kycapFile{}, fmt.Errorf("%w: manifest is %d bytes", ErrCorruptCapsule, len(cf.Manifest))
	}
	return cf, nil
}

// decryptPayload parses the container, decrypts it under the manifest, and returns the
// hash-verified gzipped tar payload.
func decryptPayload(raw, key []byte) ([]byte, error) {
	cf, err := parseContainer(raw)
	if err != nil {
		return nil, err
	}
	if cf.Ciphertext == "" {
		return nil, fmt.Errorf("%w: container carries no ciphertext", ErrCorruptCapsule)
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

func checkContainerSize(part string, size int) error {
	if size > maxContainerBytes {
		return fmt.Errorf("%w: %s is %d bytes, limit is %d", ErrCapsuleTooLarge, part, size, maxContainerBytes)
	}
	return nil
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
