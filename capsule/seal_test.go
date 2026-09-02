package capsule_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
)

func TestSealOpenRoundTrip(t *testing.T) {
	want := []capsule.File{
		{Path: "config.json", Content: []byte(`{"a":1}`), Mode: 0600},
		{Path: "keys/signing.pem", Content: bytes.Repeat([]byte("k"), 4096), Mode: 0600},
	}

	raw, key, err := capsule.Seal("fixture", "0.0.0", want, nil, nil, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "restore")
	got, err := capsule.Open(raw, key, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d files, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Path != want[i].Path {
			t.Errorf("file %d: path %q, want %q", i, got[i].Path, want[i].Path)
		}
		if !bytes.Equal(got[i].Content, want[i].Content) {
			t.Errorf("file %d (%s): content differs", i, want[i].Path)
		}
		onDisk, err := os.ReadFile(filepath.Join(dir, want[i].Path))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(onDisk, want[i].Content) {
			t.Errorf("file %d (%s): on-disk content differs", i, want[i].Path)
		}
	}
}

// Seal writes kycap/2, which binds the manifest into the AEAD. kycap/1 is still read and
// its fixtures still open, but it is no longer written: everything outside its ciphertext
// was forgeable without the key.
//
// This is a one-way step. A product still on the old reader cannot open a kycap/2 capsule,
// so readers migrate before writers do.
func TestSealWritesKycap2(t *testing.T) {
	raw, _, err := capsule.Seal("fixture", "0.0.0",
		[]capsule.File{{Path: "a.txt", Content: []byte("a"), Mode: 0600}}, nil, nil, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		Format     string `json:"format"`
		Ciphertext string `json:"ciphertext"`
		Manifest   struct {
			PayloadHash string `json:"payload_hash"`
			Threshold   int    `json:"threshold"`
			TotalShares int    `json:"total_shares"`
		} `json:"manifest"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Seal did not write JSON: %v", err)
	}
	if got.Format != capsule.KycapFileFormatV2 {
		t.Errorf("format %q, want %q", got.Format, capsule.KycapFileFormatV2)
	}
	if got.Manifest.PayloadHash == "" {
		t.Error("manifest carries no payload hash")
	}
	if got.Manifest.Threshold != 2 || got.Manifest.TotalShares != 3 {
		t.Errorf("threshold/shares %d/%d, want 2/3", got.Manifest.Threshold, got.Manifest.TotalShares)
	}
	// Standard base64 is padded to a multiple of four and never contains '-' or '_'.
	if len(got.Ciphertext)%4 != 0 {
		t.Errorf("ciphertext is not padded standard base64: len %d", len(got.Ciphertext))
	}
}

func TestSealRefusesEmptyCapsule(t *testing.T) {
	if _, _, err := capsule.Seal("x", "0", nil, nil, nil, 2, 3); err == nil {
		t.Fatal("sealed a capsule with no files")
	}
}

// Seal enforces the same containment Open does, so it can never write a capsule this
// package would then refuse to extract.
func TestSealRefusesUnsafePaths(t *testing.T) {
	for _, p := range []string{"../escape.txt", "/etc/passwd", ".."} {
		if _, _, err := capsule.Seal("x", "0",
			[]capsule.File{{Path: p, Content: []byte("x"), Mode: 0600}}, nil, nil, 2, 3); err == nil {
			t.Errorf("sealed a capsule containing %q", p)
		}
	}
}
