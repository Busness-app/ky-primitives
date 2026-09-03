package capsule

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

// The manifest is stored in the clear — TestUnverifiedManifestIsRewritableWithoutTheKey
// reads it with no key at all — so a per-member path, size and digest published there is
// published to anyone who merely holds the capsule. The digest is the serious one: an
// offline confirmation oracle, no key and no rate limit, that recovers any member drawn
// from a guessable space, and equal digests across two backups prove a signing key was
// never rotated between them.
//
// Written first against the plaintext placement, where it failed on both the path and the
// digest.
func TestFileListNeverAppearsInTheClear(t *testing.T) {
	// sha256("payload"), computed independently of this package.
	const wantSum = "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
	const wantPath = "keys/signing.key"

	priv := testRecoveryKey(t)
	raw, sealed, err := Seal("kysignon", "1.0",
		[]File{{Path: "./" + wantPath, Content: []byte("payload"), Mode: 0o644}}, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(raw, []byte(wantPath)) {
		t.Error("the container publishes the member's path in the clear")
	}
	if bytes.Contains(raw, []byte(wantSum)) {
		t.Error("the container publishes the member's SHA-256 in the clear")
	}

	var container struct {
		Manifest map[string]json.RawMessage `json:"manifest"`
	}
	if err := json.Unmarshal(raw, &container); err != nil {
		t.Fatal(err)
	}
	if _, ok := container.Manifest["files"]; ok {
		t.Error("the plaintext manifest carries a files field")
	}
	// The whole-payload hash stays: it digests a gzip stream whose ModTimes make it
	// unguessable, and it is the backstop verifyPayloadHash needs.
	if _, ok := container.Manifest["payload_hash"]; !ok {
		t.Error("the plaintext manifest lost its payload hash")
	}

	u, err := ReadUnverifiedManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Files) != 0 {
		t.Errorf("a keyless read returned %d file entries, want none", len(u.Files))
	}

	m, files, err := Open(raw, priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 1 {
		t.Fatalf("Open returned %d file entries, want 1", len(m.Files))
	}
	got := m.Files[0]
	want := FileEntry{Path: wantPath, Size: 7, Sum: wantSum, Mode: 0o600}
	if got != want {
		t.Errorf("entry = %+v, want %+v", got, want)
	}
	if len(sealed.Files) != 1 || sealed.Files[0] != want {
		t.Errorf("Seal returned %+v, Open returned %+v", sealed.Files, m.Files)
	}
	if len(files) != 1 || files[0].Path != wantPath {
		t.Errorf("Open returned files %+v", files)
	}
}

// The list is metadata, not a member of the backup.
func TestReservedMemberIsNeitherReturnedNorWritten(t *testing.T) {
	priv := testRecoveryKey(t)
	raw, _, err := Seal("t", "1",
		[]File{{Path: "a.txt", Content: []byte("a"), Mode: 0600}}, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "restore")
	_, files, err := Open(raw, priv, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "a.txt" {
		t.Fatalf("Open returned %+v, want only a.txt", files)
	}

	var written []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			written = append(written, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 || written[0] != "a.txt" {
		t.Fatalf("extraction wrote %v, want only a.txt", written)
	}
}

// A caller cannot spell the reserved name: safeRelPath normalises the attempt into a
// different member, which then round-trips like any other file while the real list is
// still decoded.
func TestAMemberNamedLikeTheListDoesNotShadowIt(t *testing.T) {
	const decoy = ".kycap-files.json"

	priv := testRecoveryKey(t)
	raw, _, err := Seal("t", "1",
		[]File{{Path: reservedFileList, Content: []byte("decoy"), Mode: 0600}}, nil, nil, 2, 3, priv.Public())
	if err != nil {
		t.Fatal(err)
	}

	m, files, err := Open(raw, priv, filepath.Join(t.TempDir(), "restore"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != decoy || !bytes.Equal(files[0].Content, []byte("decoy")) {
		t.Fatalf("Open returned %+v, want one %q holding the caller's bytes", files, decoy)
	}
	if len(m.Files) != 1 || m.Files[0].Path != decoy {
		t.Fatalf("file list = %+v, want one entry for %q", m.Files, decoy)
	}
}

// Two members under the reserved name is a crafted payload — no caller can produce one.
// It is refused rather than letting the second shadow the first.
func TestASecondReservedMemberIsRefused(t *testing.T) {
	list := []byte(`[{"path":"a.txt","size_bytes":1,"sha256":"00","mode":384}]`)
	payload := hostilePayload(t,
		[]*tar.Header{
			{Name: reservedFileList, Mode: 0600, Size: int64(len(list)), Typeflag: tar.TypeReg},
			{Name: reservedFileList, Mode: 0600, Size: int64(len(list)), Typeflag: tar.TypeReg},
		},
		[][]byte{list, list})

	if _, _, err := extractPayload(payload, ""); !errors.Is(err, ErrDuplicatePath) {
		t.Fatalf("got %v, want ErrDuplicatePath", err)
	}
}

// A capsule sealed before v0.3.0 has no reserved member. It still opens, and reports no
// entries — the honest answer, since it never carried an authenticated list. The golden
// fixture in testdata is one of these, and TestOpensEveryPersistedCapsule opens it.
func TestAPayloadWithNoListOpensWithNoEntries(t *testing.T) {
	payload := hostilePayload(t,
		[]*tar.Header{{Name: "a.txt", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}},
		[][]byte{[]byte("a")})

	files, entries, err := extractPayload(payload, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("extracted %d files, want 1", len(files))
	}
	if len(entries) != 0 {
		t.Fatalf("file list = %+v, want none", entries)
	}
}

// reservedNameAttempts are the spellings a caller might reach for. safeRelPath returns
// filepath.Clean output, and Clean never returns a "./" prefix — it drops "." elements,
// and the only "." it can return is the whole result, which safeRelPath rejects.
var reservedNameAttempts = []string{
	reservedFileList,
	".kycap-files.json",
	"././.kycap-files.json",
	".//.kycap-files.json",
	"./x/../.kycap-files.json",
	"a/./.kycap-files.json",
	"/./.kycap-files.json",
	"./.kycap-files.json/",
	"./.kycap-files.json/.",
	"\\.\\.kycap-files.json",
	"./", ".", "..", "./..",
}

func TestReservedNameIsUnreachableThroughSafeRelPath(t *testing.T) {
	for _, name := range reservedNameAttempts {
		got, err := safeRelPath(name)
		if err == nil && got == reservedFileList {
			t.Errorf("safeRelPath(%q) produced the reserved name", name)
		}
	}
	// What a caller asking for it gets instead: a different member.
	got, err := safeRelPath(reservedFileList)
	if err != nil {
		t.Fatalf("safeRelPath(%q) errored: %v", reservedFileList, err)
	}
	if got != ".kycap-files.json" {
		t.Fatalf("safeRelPath(%q) = %q, want %q", reservedFileList, got, ".kycap-files.json")
	}
}

// The same property against anything at all, not only the spellings above.
func FuzzSafeRelPathCannotProduceTheReservedName(f *testing.F) {
	for _, name := range reservedNameAttempts {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got, err := safeRelPath(name)
		if err == nil && got == reservedFileList {
			t.Fatalf("safeRelPath(%q) produced the reserved name", name)
		}
	})
}

// The list is decoded from the payload, not derived from it, so whoever holds the key can
// write one that describes nothing extraction produced: a path no member has, a digest
// for bytes that were never extracted, or more entries than members. Callers verify
// restores per-file against these entries, so every field is checked against the member.
//
// Written first against the unreconciled read path, where every hostile case passed.
func TestFileListMustDescribeTheExtractedMembers(t *testing.T) {
	// sha256("a"), computed independently of this package.
	const sumA = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
	member := &tar.Header{Name: "a.txt", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}
	honest := `{"path":"a.txt","size_bytes":1,"sha256":"` + sumA + `","mode":384}`

	cases := []struct {
		name    string
		list    string
		wantErr error
	}{
		{"matches the member", `[` + honest + `]`, nil},
		{"names a path no member has", `[{"path":"../../etc/shadow","size_bytes":1,"sha256":"` + sumA + `","mode":384}]`, ErrCorruptCapsule},
		{"digest disagrees with the member", `[{"path":"a.txt","size_bytes":1,"sha256":"` + sumA[:63] + `0","mode":384}]`, ErrCorruptCapsule},
		{"size disagrees with the member", `[{"path":"a.txt","size_bytes":2,"sha256":"` + sumA + `","mode":384}]`, ErrCorruptCapsule},
		{"mode is not the clamped one", `[{"path":"a.txt","size_bytes":1,"sha256":"` + sumA + `","mode":420}]`, ErrCorruptCapsule},
		{"has an entry too many", `[` + honest + `,` + honest + `]`, ErrCorruptCapsule},
		{"has an entry too few", `[]`, ErrCorruptCapsule},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := []byte(tc.list)
			payload := hostilePayload(t,
				[]*tar.Header{
					member,
					{Name: reservedFileList, Mode: 0600, Size: int64(len(list)), Typeflag: tar.TypeReg},
				},
				[][]byte{[]byte("a"), list})

			_, entries, err := extractPayload(payload, "")
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Path != "a.txt" {
				t.Fatalf("entries = %+v", entries)
			}
		})
	}
}
