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

func TestWriteLocalCopyRetention(t *testing.T) {
	dir := t.TempDir()
	for _, keep := range []int{0, -1} {
		if _, err := WriteLocalCopy(dir, "Svc", "cap-1", []byte("sealed"), keep); err != ErrBadKeep {
			t.Errorf("keep %d: %v", keep, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("wrote with a bad keep: %d entries", len(entries))
	}
	p, err := WriteLocalCopy(dir, "Svc", "cap-1", []byte("sealed"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Error("keep=1 pruned the copy just written")
	}
}

func TestWriteLocalCopySweepsStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, tempPrefix+"dead")
	_ = os.WriteFile(stale, []byte("half"), 0600)
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(stale, old, old)
	fresh := filepath.Join(dir, tempPrefix+"live")
	_ = os.WriteFile(fresh, []byte("half"), 0600)
	if _, err := WriteLocalCopy(dir, "Svc", "cap-1", []byte("sealed"), 3); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale temp file survived")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a temp file still being written was removed")
	}
}
