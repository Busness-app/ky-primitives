package capsule

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"
)

// Open holds the raw container, the decrypted payload and every expanded member in memory
// at once. A per-member ceiling of 4 GiB and a total of 8 GiB therefore did not bound a
// hostile capsule to something a server survives — it bounded it to several times the
// memory of the machine, and the process dies before the friendly error is returned.
//
// These are policy numbers, so the test is a policy test: it exists so that raising them
// back into gigabyte territory has to be done on purpose, in a diff that says so.
func TestExtractionBudgetsFitAServer(t *testing.T) {
	const ceiling = int64(512 << 20)

	if maxCapsuleExpandedTotal > ceiling {
		t.Errorf("total expansion budget is %d bytes; a server cannot hold that", maxCapsuleExpandedTotal)
	}
	if maxCapsuleFileBytes > maxCapsuleExpandedTotal {
		t.Errorf("a single member may be %d bytes but the whole archive only %d", maxCapsuleFileBytes, maxCapsuleExpandedTotal)
	}
	if maxSealedBytes > maxCapsuleExpandedTotal+ceiling {
		t.Errorf("sealed-member budget %d is unmoored from the expansion budget", maxSealedBytes)
	}
}

// containerMembers pulls the three members out of the tar capsule the suite actually
// persists, so the tests below build hostile containers around real ones.
func containerMembers(t *testing.T) map[string][]byte {
	t.Helper()
	raw, err := os.ReadFile("../testdata/capsules/kyrecovery.kycap")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = body
	}
	if len(out) != 3 {
		t.Fatalf("fixture has %d members, expected 3", len(out))
	}
	return out
}

func buildContainer(t *testing.T, members []struct {
	name string
	body []byte
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		if err := tw.WriteHeader(&tar.Header{
			Name: m.name, Mode: 0600, Size: int64(len(m.body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(m.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type member = struct {
	name string
	body []byte
}

// The member budget was per member and never cumulative, so the number of members was
// what made it unbounded. A container has three; anything bringing dozens is not one.
func TestTarContainerCapsMemberCount(t *testing.T) {
	real := containerMembers(t)
	var members []member
	for i := 0; i < maxContainerFiles+8; i++ {
		members = append(members, member{fmt.Sprintf("junk%d", i), []byte("x")})
	}
	for _, n := range []string{"manifest.json", "nonce.bin", "payload.enc"} {
		members = append(members, member{n, real[n]})
	}

	_, err := decryptPayload(buildContainer(t, members), make([]byte, 32))
	if !errors.Is(err, ErrUnknownContainer) {
		t.Fatalf("got %v, want ErrUnknownContainer for a container of %d members", err, len(members))
	}
}

// Every member was read into a buffer before the switch decided whether it was wanted, so
// a tar of members the container has no use for allocated all of them and then discarded
// them. Draining is the whole fix, and the only way to observe it is to weigh the walk:
// the junk below is 64 MiB, and a walk that buffers it cannot come in under that.
func TestTarContainerDrainsUnknownMembersWithoutBufferingThem(t *testing.T) {
	real := containerMembers(t)
	var members []member
	for i := 0; i < 8; i++ {
		members = append(members, member{fmt.Sprintf("junk%d", i), bytes.Repeat([]byte("x"), 8<<20)})
	}
	for _, n := range []string{"manifest.json", "nonce.bin", "payload.enc"} {
		members = append(members, member{n, real[n]})
	}
	raw := buildContainer(t, members)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _ = decryptPayload(raw, make([]byte, 32))
	runtime.ReadMemStats(&after)

	const junkBytes = 8 * (8 << 20)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > junkBytes/2 {
		t.Fatalf("the walk allocated %d bytes for %d bytes of members it does not use", grew, junkBytes)
	}
}

// Last-one-wins let a hostile tar append its own manifest after the real one and have it
// be the one that counts.
func TestTarContainerRefusesADuplicateMember(t *testing.T) {
	real := containerMembers(t)
	members := []member{
		{"manifest.json", real["manifest.json"]},
		{"nonce.bin", real["nonce.bin"]},
		{"payload.enc", real["payload.enc"]},
		{"manifest.json", []byte(`{"payload_hash":"00","aad":""}`)},
	}

	_, err := decryptPayload(buildContainer(t, members), make([]byte, 32))
	if !errors.Is(err, ErrCorruptCapsule) {
		t.Fatalf("got %v, want ErrCorruptCapsule for a repeated manifest", err)
	}
}

// A member the container does not use must cost the walk nothing but the skip.
func TestTarContainerIgnoresAnUnknownMember(t *testing.T) {
	real := containerMembers(t)
	members := []member{
		{"README.txt", []byte("not part of the format")},
		{"manifest.json", real["manifest.json"]},
		{"nonce.bin", real["nonce.bin"]},
		{"payload.enc", real["payload.enc"]},
	}

	// The fixture key is not this one, so this must fail at the AEAD, not at the walk.
	_, err := decryptPayload(buildContainer(t, members), make([]byte, 32))
	if errors.Is(err, ErrUnknownContainer) || errors.Is(err, ErrCorruptCapsule) {
		t.Fatalf("an unknown member broke the walk: %v", err)
	}
}
