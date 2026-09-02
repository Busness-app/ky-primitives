package capsule

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Seal writes a kycap/1 container and returns it with the freshly generated AES-256 key
// that opens it.
//
// Seal does not split the key into Shamir shares. The kycap/1 container has never carried
// shares — kysignon-server's SerializeCapsule writes "manifest plus ciphertext, no
// shards" — and the shares belong to the recovery kit that accompanies a capsule, not to
// the capsule itself. Callers split the returned key themselves.
func Seal(serviceName, appVersion string, files []File, deps, recipe map[string]any, threshold, totalShares int) (raw, key []byte, err error) {
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("refusing to seal a capsule with no files")
	}

	payload, err := buildPayload(files)
	if err != nil {
		return nil, nil, err
	}

	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, fmt.Errorf("failed to generate capsule key: %w", err)
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate capsule nonce: %w", err)
	}

	sum := sha256.Sum256(payload)
	sealed := gcm.Seal(nonce, nonce, payload, nil)

	raw, err = json.MarshalIndent(kycapFile{
		Format: KycapFileFormat,
		Manifest: manifest{
			CapsuleID:          fmt.Sprintf("cap-%s-%d", serviceName, time.Now().UnixNano()),
			ServiceName:        serviceName,
			AppVersion:         appVersion,
			CreatedAt:          time.Now().UTC(),
			PayloadHash:        hex.EncodeToString(sum[:]),
			Threshold:          threshold,
			TotalShares:        totalShares,
			Dependencies:       deps,
			VerificationRecipe: recipe,
		},
		Ciphertext: EncodeCiphertext(sealed),
	}, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return raw, key, nil
}

// buildPayload writes the files as a gzipped tar, the plaintext both containers hold.
func buildPayload(files []File) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for _, f := range files {
		// Seal enforces the same containment Open does, so a capsule this package writes
		// can never be one this package refuses to extract.
		name, err := safeRelPath(f.Path)
		if err != nil {
			return nil, err
		}
		mode := f.Mode.Perm() & 0700
		if mode == 0 {
			mode = 0600
		}
		hdr := &tar.Header{
			Name:     name,
			Mode:     int64(mode),
			Size:     int64(len(f.Content)),
			Typeflag: tar.TypeReg,
			ModTime:  time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Content); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
