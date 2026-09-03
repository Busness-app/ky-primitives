package keyfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCreatesAKeyOnFirstCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.key")
	key, err := LoadOrCreate(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key is %d bytes", len(key))
	}
	if bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("key is all zeros")
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("key file mode is %04o, want 0600", perm)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0700 {
		t.Errorf("key directory mode is %04o, want 0700", perm)
	}
}

func TestSecondCallReturnsTheSameKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.key")
	first, err := LoadOrCreate(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("the second call minted a different key")
	}
}

// kynotes-server continues past a key file it cannot decode and leaves the secret empty,
// so the server runs with no pairing secret at all. kypassword-server regenerates, which
// silently breaks every record written under the old key. Both are worse than refusing to
// start.
func TestRefusesToReplaceAnUnreadableKeyFile(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"not hex", "zzzz-not-hex-zzzz"},
		{"empty", ""},
		{"wrong length", "aabbccdd"},
		{"whitespace only", "   \n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.key")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadOrCreate(path, 32)
			if !errors.Is(err, ErrUnreadable) {
				t.Fatalf("got %v, want ErrUnreadable", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != tc.content {
				t.Fatal("the existing key file was overwritten")
			}
		})
	}
}

// The read was an unbounded io.ReadAll, so a corrupt or attacker-controlled file was pulled
// into memory whole before anything could refuse it. Refusing it must not replace it
// either — that is the guarantee ErrUnreadable names.
func TestReadRefusesAnOversizedFileWithoutTouchingIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.key")
	// Comfortably past 2*32+64; still a plausible file for something to leave behind.
	content := bytes.Repeat([]byte("ab"), 1<<20)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadOrCreate(path, 32)
	if !errors.Is(err, ErrUnreadable) {
		t.Fatalf("got %v, want ErrUnreadable", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, content) {
		t.Fatal("the existing key file was modified")
	}
}

// A key readable by any other account on the box is not a key. Nothing in the suite
// checks this today.
func TestRefusesAKeyFileOthersCanRead(t *testing.T) {
	for _, mode := range []os.FileMode{0640, 0604, 0644, 0660} {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.key")
		key, err := LoadOrCreate(path, 32)
		if err != nil {
			t.Fatal(err)
		}
		_ = key
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreate(path, 32); !errors.Is(err, ErrPermissive) {
			t.Errorf("mode %04o: got %v, want ErrPermissive", mode, err)
		}
	}
}

func TestRequireOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RequireOwnerOnly(path); err != nil {
		t.Fatalf("0600 rejected: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := RequireOwnerOnly(path); !errors.Is(err, ErrPermissive) {
		t.Fatalf("0644 accepted: %v", err)
	}
	if err := RequireOwnerOnly(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing file was accepted")
	}
}

func TestRejectsSymlinkKey(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(real, []byte("00"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := RequireOwnerOnly(link); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("symlink: got %v, want ErrUnsafe", err)
	}
}

// Five of the seven implementations read then write with no exclusion, so two starters
// each mint a key and one silently wins — after the loser has already sealed data under
// the key that is about to vanish.
func TestConcurrentCallersAllGetOneKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.key")
	const n = 24
	keys := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys[i], errs[i] = LoadOrCreate(path, 32)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if !bytes.Equal(keys[0], keys[i]) {
			t.Fatalf("caller %d got a different key from caller 0", i)
		}
	}
	onDisk, err := LoadOrCreate(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, keys[0]) {
		t.Fatal("the key on disk is not the one callers were handed")
	}
}

func TestRejectsASillySize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	for _, size := range []int{0, -1, 15} {
		if _, err := LoadOrCreate(path, size); err == nil {
			t.Errorf("size %d was accepted", size)
		}
	}
}

// kypassword-server writes `_, _ = rand.Read(b)`, so on a failed read the buffer stays
// zero and it ships a 32-byte all-zero pairing secret. A failure here must reach the
// caller and leave nothing behind on disk.
func TestRngFailureIsAnErrorAndWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.key")

	original := randRead
	boom := errors.New("entropy pool exhausted")
	randRead = func(b []byte) (int, error) { return 0, boom }
	t.Cleanup(func() { randRead = original })

	key, err := LoadOrCreate(path, 32)
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the RNG error", err)
	}
	if key != nil {
		t.Fatalf("a key was returned alongside the error: %x", key)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a key file was left on disk after the RNG failed")
	}
}

// Finding 3.2: the key was written directly to its final name, so a short write or a
// full disk left partial hex at the real path — which every later start then refuses
// forever, since the package correctly will not replace an unreadable key.
func TestAFailedWriteLeavesNoKeyFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.key")

	original := writeAll
	boom := errors.New("no space left on device")
	writeAll = func(f *os.File, s string) error {
		_, _ = f.WriteString(s[:len(s)/2]) // a real short write, then the failure
		return boom
	}
	t.Cleanup(func() { writeAll = original })

	if _, err := LoadOrCreate(path, 32); !errors.Is(err, boom) {
		t.Fatalf("got %v, want the write error", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a partial key file was left at the final path")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("temporary state left behind: %v", names)
	}

	// And the next attempt must succeed rather than inherit the wreckage.
	writeAll = original
	if _, err := LoadOrCreate(path, 32); err != nil {
		t.Fatalf("recovery attempt failed: %v", err)
	}
}

func TestStoreWritesTheBytesItWasGiven(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "recovery.pub")
	want := bytes.Repeat([]byte{0xAB}, 1216)
	if err := Store(path, want, Raw); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := Load(path, 1216)
	if err == nil {
		t.Fatal("Load with Hex read a Raw file; the encodings must not read each other")
	}
	got, err = LoadEncoded(path, 1216, Raw)
	if err != nil {
		t.Fatalf("LoadEncoded: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("Load returned different bytes from what Store wrote")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("stored file mode is %04o, want 0600", perm)
	}
}

// Replacing the public key file is the substitution attack: every later backup is sealed
// to whoever wrote it. Store must refuse, and the first key must survive the attempt.
func TestStoreRefusesToReplaceAnExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recovery.pub")
	first := bytes.Repeat([]byte{0x01}, 32)
	second := bytes.Repeat([]byte{0x02}, 32)
	if err := Store(path, first, Raw); err != nil {
		t.Fatal(err)
	}
	if err := Store(path, second, Raw); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second Store gave %v, want ErrExist", err)
	}
	got, err := LoadEncoded(path, 32, Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatal("the first key was replaced")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries after a refused Store, want 1", len(entries))
	}
}

func TestStoreRefusesASillySize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	if err := Store(path, make([]byte, minSize-1), Raw); err == nil {
		t.Fatal("Store accepted a key below the floor")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused Store left a file behind")
	}
}

func TestStoreRefusesAnUnknownEncoding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	if err := Store(path, make([]byte, 32), Encoding(99)); err == nil {
		t.Fatal("Store accepted an unknown encoding")
	}
}

func TestStoreSurvivesAFailedWriteWithNoFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	original := writeAll
	boom := errors.New("no space left on device")
	writeAll = func(f *os.File, s string) error {
		_, _ = f.WriteString(s[:len(s)/2])
		return boom
	}
	t.Cleanup(func() { writeAll = original })

	if err := Store(path, make([]byte, 32), Raw); !errors.Is(err, boom) {
		t.Fatalf("got %v, want the write error", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%d entries left behind after a failed Store", len(entries))
	}
}
