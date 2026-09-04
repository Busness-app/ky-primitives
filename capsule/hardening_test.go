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

// hostilePayload builds a gzipped tar directly, bypassing Seal's own containment checks,
// so the extraction path is tested against archives Seal would never produce.
func hostilePayload(t *testing.T, hdrs []*tar.Header, bodies [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for i, h := range hdrs {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if len(bodies[i]) > 0 {
			if _, err := tw.Write(bodies[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractRejectsPathTraversal(t *testing.T) {
	for _, name := range []string{
		"../escape.txt",
		"../../escape.txt",
		"/etc/passwd",
		"a/../../escape.txt",
		"..",
		"",
		"dir\\file.txt",
	} {
		t.Run(name, func(t *testing.T) {
			payload := hostilePayload(t,
				[]*tar.Header{{Name: name, Mode: 0600, Size: 3, Typeflag: tar.TypeReg}},
				[][]byte{[]byte("bad")})

			dir := filepath.Join(t.TempDir(), "restore")
			if _, _, err := extractPayload(payload, dir); !errors.Is(err, ErrPathTraversal) {
				t.Fatalf("got %v, want ErrPathTraversal", err)
			}
		})
	}
}

func TestExtractRejectsNonRegularFiles(t *testing.T) {
	for name, flag := range map[string]byte{
		"symlink":  tar.TypeSymlink,
		"hardlink": tar.TypeLink,
		"dir":      tar.TypeDir,
		"chardev":  tar.TypeChar,
		"fifo":     tar.TypeFifo,
	} {
		t.Run(name, func(t *testing.T) {
			payload := hostilePayload(t,
				[]*tar.Header{{Name: "evil", Mode: 0600, Typeflag: flag, Linkname: "/etc/passwd"}},
				[][]byte{nil})

			dir := filepath.Join(t.TempDir(), "restore")
			if _, _, err := extractPayload(payload, dir); !errors.Is(err, ErrCapsuleEntryType) {
				t.Fatalf("got %v, want ErrCapsuleEntryType", err)
			}
		})
	}
}

// A symlink entry is the classic way to redirect a restore. Prove nothing landed outside
// the target when one is refused.
func TestExtractWritesNothingOutsideTarget(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside.txt")
	dir := filepath.Join(base, "restore")

	payload := hostilePayload(t,
		[]*tar.Header{{Name: "../outside.txt", Mode: 0600, Size: 5, Typeflag: tar.TypeReg}},
		[][]byte{[]byte("pwned")})

	if _, _, err := extractPayload(payload, dir); err == nil {
		t.Fatal("traversal entry extracted without error")
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("a file was written outside the target directory: %v", err)
	}
}

func TestExtractRefusesNonEmptyTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "squatter"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	payload := hostilePayload(t,
		[]*tar.Header{{Name: "ok.txt", Mode: 0600, Size: 2, Typeflag: tar.TypeReg}},
		[][]byte{[]byte("ok")})

	if _, _, err := extractPayload(payload, dir); !errors.Is(err, ErrTargetNotEmpty) {
		t.Fatalf("got %v, want ErrTargetNotEmpty", err)
	}
}

func TestExtractRejectsTooManyFiles(t *testing.T) {
	var hdrs []*tar.Header
	var bodies [][]byte
	for i := 0; i <= MaxFiles; i++ {
		hdrs = append(hdrs, &tar.Header{
			Name:     fmt.Sprintf("d/f%d.txt", i),
			Mode:     0600,
			Size:     1,
			Typeflag: tar.TypeReg,
		})
		bodies = append(bodies, []byte("x"))
	}
	payload := hostilePayload(t, hdrs, bodies)

	if _, _, err := extractPayload(payload, ""); !errors.Is(err, ErrCapsuleTooLarge) {
		t.Fatalf("got %v, want ErrCapsuleTooLarge", err)
	}
}

// An archive header is attacker-controlled. A restored capsule carries keys, so no header
// may land a group- or world-readable file.
func TestExtractClampsModeToOwnerOnly(t *testing.T) {
	payload := hostilePayload(t,
		[]*tar.Header{
			{Name: "world.txt", Mode: 0777, Size: 1, Typeflag: tar.TypeReg},
			{Name: "setuid.txt", Mode: 04755, Size: 1, Typeflag: tar.TypeReg},
			{Name: "zero.txt", Mode: 0, Size: 1, Typeflag: tar.TypeReg},
		},
		[][]byte{[]byte("a"), []byte("b"), []byte("c")})

	dir := filepath.Join(t.TempDir(), "restore")
	files, _, err := extractPayload(payload, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Mode&^os.FileMode(0700) != 0 {
			t.Errorf("%s: mode %o leaks past owner-only", f.Path, f.Mode)
		}
		fi, err := os.Stat(filepath.Join(dir, f.Path))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&^os.FileMode(0700) != 0 {
			t.Errorf("%s: on-disk mode %o leaks past owner-only", f.Path, fi.Mode().Perm())
		}
	}
}

// A NUL in a member name cannot be tested through the tar writer — Go refuses to encode
// one — so the check is exercised where it lives. Names that never reach a tar can still
// reach safeRelPath from a future non-tar container.
func TestSafeRelPathRejects(t *testing.T) {
	for _, name := range []string{
		"",
		"a\x00b",
		"..",
		".",
		"../escape",
		"/abs/path",
		"dir\\file",
		"a/../../escape",
	} {
		if _, err := safeRelPath(name); !errors.Is(err, ErrPathTraversal) {
			t.Errorf("safeRelPath(%q) = %v, want ErrPathTraversal", name, err)
		}
	}
}

func TestSafeRelPathAccepts(t *testing.T) {
	for name, want := range map[string]string{
		"config.json":      "config.json",
		"a/b/c.txt":        "a/b/c.txt",
		"./config.json":    "config.json",
		"a/./b.txt":        "a/b.txt",
		"a/b/../c.txt":     "a/c.txt",
		"deep/nested/f.db": "deep/nested/f.db",
	} {
		got, err := safeRelPath(name)
		if err != nil {
			t.Errorf("safeRelPath(%q) errored: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("safeRelPath(%q) = %q, want %q", name, got, want)
		}
	}
}
