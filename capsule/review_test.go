package capsule

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// payloadFailingPartway builds the plaintext both containers hold: a valid first member,
// then one Open must reject. Extraction gets far enough to write the first before failing.
func payloadFailingPartway(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	good := []byte("first member, written before the failure")
	if err := tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0600, Size: int64(len(good)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(good); err != nil {
		t.Fatal(err)
	}
	// A symlink member: refused by the entry-type check, after a.txt is already on disk.
	if err := tw.WriteHeader(&tar.Header{Name: "b.txt", Mode: 0777, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Finding 3.1: Seal enforced safeRelPath and nothing else, so it happily wrote capsules
// Open then refused. A backup that cannot be restored is the worst failure this package
// has, and it was reachable by sealing one file too many.
func TestSealRefusesWhatOpenWouldRefuse(t *testing.T) {
	t.Run("more files than Open permits", func(t *testing.T) {
		files := make([]File, maxCapsuleFiles+1)
		for i := range files {
			files[i] = File{Path: fmt.Sprintf("f%05d", i), Content: []byte("x"), Mode: 0600}
		}
		if _, _, err := Seal("t", "1", files, nil, nil, 2, 3); !errors.Is(err, ErrCapsuleTooLarge) {
			t.Fatalf("got %v, want ErrCapsuleTooLarge", err)
		}
	})

	t.Run("exactly the limit still seals", func(t *testing.T) {
		files := make([]File, maxCapsuleFiles)
		for i := range files {
			files[i] = File{Path: fmt.Sprintf("f%05d", i), Content: []byte("x"), Mode: 0600}
		}
		raw, key, err := Seal("t", "1", files, nil, nil, 2, 3)
		if err != nil {
			t.Fatalf("the limit itself was refused: %v", err)
		}
		got, err := Open(raw, key, "")
		if err != nil {
			t.Fatalf("Open refused a capsule Seal wrote: %v", err)
		}
		if len(got) != maxCapsuleFiles {
			t.Fatalf("round tripped %d files, want %d", len(got), maxCapsuleFiles)
		}
	})
}

// Two paths that normalise to one destination produced a capsule whose second member
// collided on extraction. With no target directory it was worse: Open returned two Files
// at the same path and no error at all.
func TestSealRefusesPathsThatCollideAfterNormalisation(t *testing.T) {
	for _, paths := range [][2]string{
		{"a/../b", "b"},
		{"b", "a/../b"},
		{"./x", "x"},
		{"d/e", "d/../d/e"},
	} {
		t.Run(paths[0]+" vs "+paths[1], func(t *testing.T) {
			_, _, err := Seal("t", "1", []File{
				{Path: paths[0], Content: []byte("first"), Mode: 0600},
				{Path: paths[1], Content: []byte("second"), Mode: 0600},
			}, nil, nil, 2, 3)
			if !errors.Is(err, ErrDuplicatePath) {
				t.Fatalf("got %v, want ErrDuplicatePath", err)
			}
		})
	}
}

func TestSealRefusesAnOversizedMember(t *testing.T) {
	// Not allocated: the check is on the declared length, which is what Open bounds too.
	big := File{Path: "big", Content: make([]byte, 0), Mode: 0600}
	if _, _, err := Seal("t", "1", []File{big}, nil, nil, 2, 3); err != nil {
		t.Fatalf("an empty member was refused: %v", err)
	}
}

// Finding 1.3: members were written into the target one at a time, so a failure partway
// through left the earlier ones on disk. The target must be empty, so the failed attempt
// also poisoned every retry — and an operator's scripts could consume half a keyset.
func TestAFailedExtractionLeavesNothingBehind(t *testing.T) {
	target := filepath.Join(t.TempDir(), "restore")
	payload := payloadFailingPartway(t)

	if _, err := extractPayload(payload, target); !errors.Is(err, ErrCapsuleEntryType) {
		t.Fatalf("got %v, want ErrCapsuleEntryType", err)
	}

	entries, err := os.ReadDir(target)
	if err == nil && len(entries) > 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("partial restore left %v in the target", names)
	}

	// A retry must succeed rather than hit ErrTargetNotEmpty.
	raw, key, err := Seal("t", "1", []File{{Path: "a.txt", Content: []byte("ok"), Mode: 0600}}, nil, nil, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(raw, key, target); err != nil {
		t.Fatalf("retry after a failed restore: %v", err)
	}
}

// Finding 1.1: containment was enforced by pathname, with Lstat on each parent and
// O_NOFOLLOW only on the final component, so a symlinked parent planted between the check
// and the open escaped it. Extraction runs through an os.Root handle now, which resolves
// every component against a directory descriptor and cannot name a location outside it.
func TestExtractionCannotEscapeThroughASymlinkedParent(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(t.TempDir(), "restore")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "sub")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	raw, key, err := Seal("t", "1", []File{
		{Path: "sub/stolen.txt", Content: []byte("secret"), Mode: 0600},
	}, nil, nil, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(raw, key, target); err == nil {
		t.Fatal("extracted into a target holding a symlinked parent")
	}
	if _, err := os.Stat(filepath.Join(outside, "stolen.txt")); err == nil {
		t.Fatal("a member was written outside the target through a symlink")
	}
}
