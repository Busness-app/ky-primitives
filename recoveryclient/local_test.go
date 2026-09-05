package recoveryclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteLocalCopyPrunesOwnPrefixOnly(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"foreign.kycap", "Other-cap-Other-1.kycap"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("not ours"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var last string
	for i := 0; i < 3; i++ {
		p, err := WriteLocalCopy(dir, "Svc", "cap-Svc-"+strings.Repeat("1", i+1), []byte("sealed"), 2)
		if err != nil {
			t.Fatal(err)
		}
		last = p
		time.Sleep(15 * time.Millisecond)
	}
	copies, err := ListLocalCopies(dir, "Svc")
	if err != nil || len(copies) != 2 || copies[0].Name != filepath.Base(last) {
		t.Fatalf("%+v %v", copies, err)
	}
	for _, c := range copies {
		if !strings.HasPrefix(c.Name, "Svc-") {
			t.Errorf("listed %s", c.Name)
		}
	}
	for _, f := range []string{"foreign.kycap", "Other-cap-Other-1.kycap"} {
		if b, err := os.ReadFile(filepath.Join(dir, f)); err != nil || string(b) != "not ours" {
			t.Errorf("%s touched: %v", f, err)
		}
	}
	if info, _ := os.Stat(last); info.Mode().Perm() != 0600 {
		t.Errorf("mode %v", info.Mode())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 4 {
		t.Errorf("%d entries; a temp file leaked?", len(entries))
	}
}

func TestListLocalCopiesMissingDirIsEmpty(t *testing.T) {
	copies, err := ListLocalCopies(filepath.Join(t.TempDir(), "nope"), "Svc")
	if err != nil || len(copies) != 0 {
		t.Fatalf("%v %v", copies, err)
	}
	if copies, err := ListLocalCopies("", "Svc"); err != nil || copies != nil {
		t.Fatalf("empty dir arg: %v %v", copies, err)
	}
}
