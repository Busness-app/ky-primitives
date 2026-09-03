package capsule

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// FileEntry describes one member of the payload. The digest lets a restore say which file
// is wrong; the payload hash only says that one of them is.
type FileEntry struct {
	Path string      `json:"path"`
	Size int64       `json:"size_bytes"`
	Sum  string      `json:"sha256"`
	Mode os.FileMode `json:"mode"`
}

// UnverifiedManifest is a capsule's manifest read without its key.
//
// Every field here is attacker-controlled wherever the capsule file is. The manifest is
// bound into the AEAD exactly so that threshold, total_shares and the verification recipe
// cannot be rewritten by whoever reaches the file — that is what kycap/1 got wrong, where
// a 2-of-3 kit could be restated as 1-of-1 and still open. Reading it without the key
// gives that guarantee up.
//
// So it is a distinct type from Manifest. The compiler stops one being passed where the
// other is required, which catches the accident — it cannot stop deliberate construction,
// because Manifest's only field is exported and a caller may write Manifest{...} itself.
// The type is a guard rail, not a proof. Show these fields to an operator if you must; do
// not decide anything on them. Anything that chooses a restore path, a quorum, or a
// verification rule wants Manifest, which only a successful Open or Seal produces.
type UnverifiedManifest struct {
	CapsuleID   string      `json:"capsule_id"`
	ServiceName string      `json:"service_name"`
	AppVersion  string      `json:"app_version"`
	CreatedAt   time.Time   `json:"created_at"`
	PayloadHash string      `json:"payload_hash"`
	Threshold   int         `json:"threshold"`
	TotalShares int         `json:"total_shares"`
	Files       []FileEntry `json:"files,omitempty"`

	Dependencies       any `json:"dependencies,omitempty"`
	VerificationRecipe any `json:"verification_recipe,omitempty"`
}

// Manifest is a capsule's manifest, authenticated. Only Open returns one.
//
// The embedded field is not an accident: a Manifest can be read wherever the fields are
// wanted, but an UnverifiedManifest cannot be passed where a Manifest is required.
//
// A Manifest is authenticated, not validated. Open proves the manifest is the one that was
// sealed under this key; it does not re-apply Seal's topology rule, so a kit recorded as
// 0-of-0 by some other writer opens without complaint. Check the numbers you intend to act
// on.
type Manifest struct {
	UnverifiedManifest
}

// ReadUnverifiedManifest returns a capsule's manifest without decrypting it and without a
// key. Read the doc comment on UnverifiedManifest before using it.
func ReadUnverifiedManifest(raw []byte) (UnverifiedManifest, error) {
	cf, err := parseContainer(raw)
	if err != nil {
		return UnverifiedManifest{}, err
	}
	var m UnverifiedManifest
	if err := json.Unmarshal(cf.Manifest, &m); err != nil {
		return UnverifiedManifest{}, fmt.Errorf("%w: unreadable manifest: %v", ErrCorruptCapsule, err)
	}
	return m, nil
}
