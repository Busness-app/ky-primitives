package capsule_test

import (
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
