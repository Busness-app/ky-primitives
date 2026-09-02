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

// KycapFileFormat identifies the legacy JSON container. It is still read, and no longer
// written: everything outside its ciphertext is unauthenticated.
const KycapFileFormat = "kycap/1"

// KycapFileFormatV2 identifies the JSON container this package writes. It is kycap/1 with
// the manifest bound into the AEAD as additional authenticated data.
const KycapFileFormatV2 = "kycap/2"

// Container member budgets for the tar walk. The three members are a small JSON manifest,
// a 12-byte nonce and the sealed payload; nothing here is large, and a member that claims
// to be is either corrupt or hostile.
const (
	maxManifestBytes  = int64(1 << 20) // 1 MiB of JSON is already absurd for a manifest
	maxNonceBytes     = int64(64)      // a GCM nonce is 12
	maxSealedBytes    = maxCapsuleExpandedTotal + (1 << 20)
	maxContainerFiles = 16
)

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

// kycapFile is the JSON container, in both versions.
//
// Manifest is kept as raw bytes rather than a decoded struct because in kycap/2 those
// exact bytes are the additional authenticated data. Re-encoding a decoded manifest to
// rebuild the AAD would have to reproduce the writer's spelling byte for byte — field
// order, number formatting, the interface{} shape of dependencies — and any drift there
// fails every capsule rather than any forgery. The bytes that were read are the bytes
// that are authenticated.
type kycapFile struct {
	Format     string          `json:"format"`
	Manifest   json.RawMessage `json:"manifest"`
	Ciphertext string          `json:"ciphertext"`
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

// decryptKycap1 reads the JSON container in either version: nonce prefixed to the
// ciphertext, and in kycap/2 the manifest bytes bound in as AAD.
func decryptKycap1(raw, key []byte) ([]byte, error) {
	var cf kycapFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		return nil, fmt.Errorf("%w: not readable as %s: %v", ErrUnknownContainer, KycapFileFormat, err)
	}
	// aad stays nil for kycap/1. Binding the manifest there would break every capsule
	// already on disk, which was written without it.
	var aad []byte
	switch cf.Format {
	case KycapFileFormat:
	case KycapFileFormatV2:
		aad = cf.Manifest
	default:
		return nil, fmt.Errorf("%w: unsupported capsule format %q", ErrUnknownContainer, cf.Format)
	}
	if cf.Ciphertext == "" {
		return nil, fmt.Errorf("%w: container carries no ciphertext", ErrCorruptCapsule)
	}
	if int64(len(cf.Manifest)) > maxManifestBytes {
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

	payload, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt capsule: %w", err)
	}
	return payload, verifyPayloadHash(payload, m.PayloadHash)
}

// decryptTarContainer reads kyrecovery-server's tar container: nonce in its own member,
// and the manifest's aad field bound into the AEAD.
func decryptTarContainer(raw, key []byte) ([]byte, error) {
	var manifestBytes, nonce, sealed []byte

	// Each member gets the budget its role justifies, and a member this container has no
	// use for is drained rather than read. Reading every member into a buffer before
	// discarding it let a tar of large junk members allocate without bound while none of
	// it was ever used, and a single per-member limit of the whole payload size meant the
	// budget never applied to the archive as a whole.
	limits := map[string]int64{
		"manifest.json": maxManifestBytes,
		"nonce.bin":     maxNonceBytes,
		"payload.enc":   maxSealedBytes,
	}
	seen := make(map[string]bool, len(limits))

	tr := tar.NewReader(bytes.NewReader(raw))
	for members := 0; ; members++ {
		if members >= maxContainerFiles {
			return nil, fmt.Errorf("%w: more than %d members", ErrUnknownContainer, maxContainerFiles)
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnknownContainer, err)
		}

		limit, wanted := limits[hdr.Name]
		if !wanted {
			// Drained, not buffered: an unknown member must cost the walk nothing but the
			// time to skip it.
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrUnknownContainer, err)
			}
			continue
		}
		// A repeated member is ambiguous about which copy is authentic, and last-one-wins
		// let a hostile tar append its own manifest after the real one.
		if seen[hdr.Name] {
			return nil, fmt.Errorf("%w: %s appears twice", ErrCorruptCapsule, hdr.Name)
		}
		seen[hdr.Name] = true

		data, err := io.ReadAll(io.LimitReader(tr, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrCapsuleTooLarge, hdr.Name, limit)
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
