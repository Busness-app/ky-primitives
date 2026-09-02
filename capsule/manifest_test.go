package capsule_test

import (
	"encoding/json"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
)

func TestReadUnverifiedManifestNeedsNoKey(t *testing.T) {
	files := []capsule.File{{Path: "db.sqlite", Content: []byte("payload"), Mode: 0o600}}
	raw, _, err := capsule.Seal("kyrecovery", "2.1", files, nil, nil, 3, 5)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		t.Fatalf("ReadUnverifiedManifest: %v", err)
	}
	if got.ServiceName != "kyrecovery" {
		t.Errorf("ServiceName = %q, want %q", got.ServiceName, "kyrecovery")
	}
	if got.AppVersion != "2.1" {
		t.Errorf("AppVersion = %q, want %q", got.AppVersion, "2.1")
	}
	if got.Threshold != 3 || got.TotalShares != 5 {
		t.Errorf("kit = %d-of-%d, want 3-of-5", got.Threshold, got.TotalShares)
	}
	if got.CapsuleID == "" {
		t.Error("CapsuleID is empty")
	}
}

// The manifest read without a key is unauthenticated: anyone who can reach the file can
// rewrite it. This test is the reason the two types are distinct — it demonstrates the
// rewrite, so the type boundary is not merely decorative.
func TestUnverifiedManifestIsRewritableWithoutTheKey(t *testing.T) {
	files := []capsule.File{{Path: "db.sqlite", Content: []byte("payload"), Mode: 0o600}}
	raw, key, err := capsule.Seal("kyrecovery", "2.1", files, nil, nil, 3, 5)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal container: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(doc["manifest"], &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	m["threshold"] = 1
	m["total_shares"] = 1
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	doc["manifest"] = tampered
	forged, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("remarshal container: %v", err)
	}

	// The unverified read believes the forgery. That is its nature.
	got, err := capsule.ReadUnverifiedManifest(forged)
	if err != nil {
		t.Fatalf("ReadUnverifiedManifest: %v", err)
	}
	if got.Threshold != 1 {
		t.Fatalf("Threshold = %d, want the forged 1", got.Threshold)
	}

	// Open does not. This is the line that makes the type split worth having.
	if _, _, err := capsule.Open(forged, key, ""); err == nil {
		t.Fatal("Open accepted a rewritten manifest")
	}
}
