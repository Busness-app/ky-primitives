package capsule_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
)

func sealOne(t *testing.T, to recoverykey.PublicKey) []byte {
	t.Helper()
	raw, _, err := capsule.Seal("fixture", "0.0.0",
		[]capsule.File{{Path: "a.txt", Content: []byte("a"), Mode: 0600}}, nil, nil, 2, 3, to)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// rewriteManifest re-encodes the plaintext manifest with one field replaced. The AAD is
// the manifest's exact bytes, so the result must fail Open whatever the field.
func rewriteManifest(t *testing.T, raw []byte, field string, value any) []byte {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(doc["manifest"], &m); err != nil {
		t.Fatal(err)
	}
	m[field] = value
	mb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	doc["manifest"] = mb
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// sameLengthEdit replaces one field value with another of exactly the same length, so the
// container's bytes change only where the value sits. Re-marshalling would reorder or
// respace the manifest and fail the AEAD for reasons unrelated to the field under test.
func sameLengthEdit(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	if len(from) != len(to) {
		t.Fatalf("edit changes length (%d -> %d), which would prove nothing", len(from), len(to))
	}
	if !bytes.Contains(raw, []byte(from)) {
		t.Fatalf("cannot tamper: %q is not in the container", from)
	}
	return bytes.Replace(raw, []byte(from), []byte(to), 1)
}

func TestSealedManifestNamesTheRecoveryKey(t *testing.T) {
	priv := testRecoveryKey(t)
	raw, m, err := capsule.Seal("fixture", "0.0.0",
		[]capsule.File{{Path: "a.txt", Content: []byte("a"), Mode: 0600}}, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if m.RecoveryKeyID != priv.Public().ID() {
		t.Fatalf("sealed manifest names %q, want %q", m.RecoveryKeyID, priv.Public().ID())
	}
	opened, _, err := capsule.Open(raw, priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if opened.RecoveryKeyID != m.RecoveryKeyID || opened.EncapsulatedKey != m.EncapsulatedKey {
		t.Fatal("Open returned different key fields from the ones Seal reported")
	}
}

// The wrong kit fails by name, and before decapsulation: the encapsulated key here is
// garbage, which would produce a different error if decapsulation ran first.
func TestWrongRecoveryKeyFailsByNameBeforeDecapsulation(t *testing.T) {
	sealer := testRecoveryKey(t)
	wrong := testRecoveryKey(t)
	raw := rewriteManifest(t, sealOne(t, sealer.Public()), "encapsulated_key", "AAAA")

	_, _, err := capsule.Open(raw, wrong, "")
	if !errors.Is(err, capsule.ErrWrongRecoveryKey) {
		t.Fatalf("got %v, want ErrWrongRecoveryKey", err)
	}
}

// The ID compare is a courtesy, not the security check. Forge the ID to match the wrong
// key and the AEAD is what refuses it — which proves the field is inside the AAD.
func TestForgedRecoveryKeyIDFailsAtTheAEAD(t *testing.T) {
	sealer := testRecoveryKey(t)
	wrong := testRecoveryKey(t)
	// Both IDs are 64 hex characters, so this changes exactly the field and nothing else.
	raw := sameLengthEdit(t, sealOne(t, sealer.Public()), sealer.Public().ID(), wrong.Public().ID())

	_, _, err := capsule.Open(raw, wrong, "")
	if err == nil {
		t.Fatal("a capsule opened under a key it was not sealed to")
	}
	if errors.Is(err, capsule.ErrWrongRecoveryKey) {
		t.Fatal("the forged ID passed the compare, as intended, but then reported ErrWrongRecoveryKey")
	}
	if errors.Is(err, capsule.ErrCorruptCapsule) {
		t.Fatalf("reported as ErrCorruptCapsule, want the AEAD failure: %v", err)
	}
}

// Swapping in another valid encapsulated key must fail the AEAD, not decrypt to garbage.
func TestSwappedEncapsulatedKeyFailsAtTheAEAD(t *testing.T) {
	priv := testRecoveryKey(t)
	a := sealOne(t, priv.Public())
	b := sealOne(t, priv.Public())

	ua, err := capsule.ReadUnverifiedManifest(a)
	if err != nil {
		t.Fatal(err)
	}
	ub, err := capsule.ReadUnverifiedManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	// Both encapsulations are 1120 bytes, so their base64 is the same length: only the
	// field changes.
	swapped := sameLengthEdit(t, a, ua.EncapsulatedKey, ub.EncapsulatedKey)

	if _, _, err := capsule.Open(swapped, priv, ""); err == nil {
		t.Fatal("a capsule opened with another capsule's encapsulated key")
	}
}

// The keyless reader believes a rewritten key ID. That is its nature, and it is why
// kyrecovery may display the ID but must pin it against what it handed out, not trust it.
func TestUnverifiedReaderBelievesARewrittenRecoveryKeyID(t *testing.T) {
	priv := testRecoveryKey(t)
	forged := rewriteManifest(t, sealOne(t, priv.Public()), "recovery_key_id", "0000")

	u, err := capsule.ReadUnverifiedManifest(forged)
	if err != nil {
		t.Fatal(err)
	}
	if u.RecoveryKeyID != "0000" {
		t.Fatalf("unverified read gave %q, want the forged 0000", u.RecoveryKeyID)
	}
	if _, _, err := capsule.Open(forged, priv, ""); err == nil {
		t.Fatal("Open accepted the forged ID")
	}
}

// A kycap/2 container is refused at the format check, before any key is looked at.
func TestKycap2IsRefusedAsUnknown(t *testing.T) {
	priv := testRecoveryKey(t)
	raw := bytes.Replace(sealOne(t, priv.Public()), []byte(`"format":"kycap/3"`), []byte(`"format":"kycap/2"`), 1)
	if !bytes.Contains(raw, []byte(`"kycap/2"`)) {
		t.Fatal("test setup: format field not found where expected")
	}
	if _, _, err := capsule.Open(raw, priv, ""); !errors.Is(err, capsule.ErrUnknownContainer) {
		t.Fatalf("got %v, want ErrUnknownContainer", err)
	}
}
