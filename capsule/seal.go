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

// Seal writes a kycap/2 container and returns it with the freshly generated AES-256 key
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
	// The same invariant shamir.Split enforces. A capsule states its recovery topology in
	// the manifest, and a capsule advertising 5-of-3 — or 0-of-3, which reads as "no
	// shares needed" — sends a custodian looking for a kit that was never issuable.
	// Recording the number without checking it makes the manifest decoration.
	if threshold < 2 || totalShares < threshold || totalShares > 255 {
		return nil, nil, fmt.Errorf("capsule: %d-of-%d is not a recoverable kit; need 2 <= threshold <= total <= 255", threshold, totalShares)
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

	entries := make([]FileEntry, 0, len(files))
	for _, f := range files {
		fsum := sha256.Sum256(f.Content)
		entries = append(entries, FileEntry{
			Path: f.Path,
			Size: int64(len(f.Content)),
			Sum:  hex.EncodeToString(fsum[:]),
			Mode: f.Mode,
		})
	}

	now := time.Now().UTC()
	// Marshalled once, then used twice: these bytes are the AAD and they are what lands
	// in the container. Deriving the AAD from a second encoding of the same struct would
	// make every capsule depend on two encoders agreeing forever.
	manifestBytes, err := json.Marshal(manifest{
		CapsuleID:          fmt.Sprintf("cap-%s-%d", serviceName, now.UnixNano()),
		ServiceName:        serviceName,
		AppVersion:         appVersion,
		CreatedAt:          now,
		PayloadHash:        hex.EncodeToString(sum[:]),
		Threshold:          threshold,
		TotalShares:        totalShares,
		Files:              entries,
		Dependencies:       deps,
		VerificationRecipe: recipe,
	})
	if err != nil {
		return nil, nil, err
	}

	sealed := gcm.Seal(nonce, nonce, payload, manifestBytes)

	// json.Marshal rather than MarshalIndent: indenting re-spaces the embedded manifest,
	// and the AAD is the manifest's exact bytes. A pretty container that cannot be opened
	// is not a trade worth making.
	raw, err = json.Marshal(kycapFile{
		Format:     KycapFileFormat,
		Manifest:   manifestBytes,
		Ciphertext: EncodeCiphertext(sealed),
	})
	if err != nil {
		return nil, nil, err
	}
	return raw, key, nil
}

// buildPayload writes the files as a gzipped tar, the plaintext both containers hold.
//
// Every limit Open enforces is enforced here too. Sealing is the only place the failure
// is cheap: a capsule that Open refuses is a backup that cannot be restored, and it was
// previously reachable by sealing one file past the limit, or two paths that normalise to
// one destination.
func buildPayload(files []File) ([]byte, error) {
	if len(files) > maxCapsuleFiles {
		return nil, fmt.Errorf("%w: %d files, Open permits %d", ErrCapsuleTooLarge, len(files), maxCapsuleFiles)
	}
	var total int64
	seen := make(map[string]struct{}, len(files))

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
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicatePath, name)
		}
		seen[name] = struct{}{}

		size := int64(len(f.Content))
		if size > maxCapsuleFileBytes {
			return nil, fmt.Errorf("%w: %q is %d bytes, Open permits %d", ErrCapsuleTooLarge, name, size, maxCapsuleFileBytes)
		}
		total += size
		if total > maxCapsuleExpandedTotal {
			return nil, fmt.Errorf("%w: payload exceeds %d bytes", ErrCapsuleTooLarge, maxCapsuleExpandedTotal)
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
