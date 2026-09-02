package auditchain

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

var key = bytes.Repeat([]byte{0x5a}, 32)

func build(t *testing.T, rows ...[]string) []Record {
	t.Helper()
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	var out []Record
	for _, fields := range rows {
		rec, err := c.Append(fields...)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

func TestVerifyAcceptsAnIntactChain(t *testing.T) {
	records := build(t, []string{"login", "alice"}, []string{"export", "alice"}, []string{"delete", "bob"})
	if err := Verify(key, records, Anchor{Count: 3, Hash: records[2].Hash}); err != nil {
		t.Fatal(err)
	}
}

func TestAppendLinksEachRecordToItsPredecessor(t *testing.T) {
	records := build(t, []string{"a"}, []string{"b"})
	if records[0].Seq != 1 || records[1].Seq != 2 {
		t.Fatalf("sequence numbers are %d and %d", records[0].Seq, records[1].Seq)
	}
	if records[1].Prev != records[0].Hash {
		t.Fatal("second record does not carry the first record's hash")
	}
	if records[0].Prev != strings.Repeat("0", 64) {
		t.Fatalf("genesis prev is %q", records[0].Prev)
	}
}

func TestVerifyRejectsAnEditedField(t *testing.T) {
	records := build(t, []string{"login", "alice"}, []string{"export", "alice"})
	records[0].Fields[1] = "bob"
	err := Verify(key, records, Anchor{Count: 2, Hash: records[1].Hash})
	if !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("got %v, want ErrBrokenChain", err)
	}
}

func TestVerifyRejectsARemovedRecord(t *testing.T) {
	records := build(t, []string{"a"}, []string{"b"}, []string{"c"})
	spliced := []Record{records[0], records[2]}
	if err := Verify(key, spliced, Anchor{Count: 3, Hash: records[2].Hash}); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("got %v, want ErrBrokenChain", err)
	}
}

// Hashes alone cannot catch this: what remains still chains correctly. The anchor is the
// only thing that does.
func TestVerifyRejectsATruncatedTail(t *testing.T) {
	records := build(t, []string{"a"}, []string{"b"}, []string{"c"})
	anchor := Anchor{Count: 3, Hash: records[2].Hash}
	if err := Verify(key, records[:2], anchor); !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
	if err := Verify(key, nil, anchor); !errors.Is(err, ErrTruncated) {
		t.Fatalf("empty log: got %v, want ErrTruncated", err)
	}
}

func TestVerifyRejectsAWrongKey(t *testing.T) {
	records := build(t, []string{"a"}, []string{"b"})
	other := bytes.Repeat([]byte{0x11}, 32)
	if err := Verify(other, records, Anchor{Count: 2, Hash: records[1].Hash}); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("got %v, want ErrBrokenChain", err)
	}
}

// kypassword and kybookmarks join fields with a bare "|". A field containing the
// delimiter can then be shifted into its neighbour without changing the digest, forging
// a record without the key. Length prefixing is what closes it.
func TestFieldsAreUnambiguousAcrossDelimiters(t *testing.T) {
	for _, pair := range [][2][]string{
		{{"a|b", "c"}, {"a", "b|c"}},
		{{"", "ab"}, {"a", "b"}},
		{{"login", ""}, {"", "login"}},
		{{"a\x00b", "c"}, {"a", "b\x00c"}},
	} {
		left := build(t, pair[0])
		right := build(t, pair[1])
		if left[0].Hash == right[0].Hash {
			t.Errorf("%q and %q hash identically", pair[0], pair[1])
		}
	}
}

func TestNewRejectsAWeakKey(t *testing.T) {
	for _, k := range [][]byte{nil, {}, bytes.Repeat([]byte{1}, 31)} {
		if _, err := New(k); !errors.Is(err, ErrWeakKey) {
			t.Errorf("New(%d bytes) = %v, want ErrWeakKey", len(k), err)
		}
	}
	if _, err := New(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("32 bytes rejected: %v", err)
	}
}

func TestVerifyRejectsAnAppendedForgery(t *testing.T) {
	records := build(t, []string{"a"}, []string{"b"})
	anchor := Anchor{Count: 2, Hash: records[1].Hash}
	forged := append(records, Record{Seq: 3, Prev: records[1].Hash, Hash: records[1].Hash, Fields: []string{"grant-admin"}})
	if err := Verify(key, forged, anchor); err == nil {
		t.Fatal("a record appended without the key verified")
	}
}

func TestResumeContinuesAnExistingChain(t *testing.T) {
	first := build(t, []string{"a"}, []string{"b"})
	c, err := Resume(key, first[len(first)-1])
	if err != nil {
		t.Fatal(err)
	}
	third, err := c.Append("c")
	if err != nil {
		t.Fatal(err)
	}
	all := append(first, third)
	if err := Verify(key, all, Anchor{Count: 3, Hash: third.Hash}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsASequenceGap(t *testing.T) {
	records := build(t, []string{"a"}, []string{"b"})
	records[1].Seq = 9
	if err := Verify(key, records, Anchor{Count: 2, Hash: records[1].Hash}); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("got %v, want ErrBrokenChain", err)
	}
}

func TestAnchorTracksTheChain(t *testing.T) {
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Anchor(); got.Count != 0 {
		t.Fatalf("fresh chain anchor is %+v", got)
	}
	rec, err := c.Append("a")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Anchor(); got.Count != 1 || got.Hash != rec.Hash {
		t.Fatalf("anchor is %+v, want count 1 and hash %s", got, rec.Hash)
	}
}
