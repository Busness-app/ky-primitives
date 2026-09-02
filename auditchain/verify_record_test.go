package auditchain_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Busness-app/ky-primitives/auditchain"
)

func appendOne(t *testing.T, key []byte, fields ...string) auditchain.Record {
	t.Helper()
	c, err := auditchain.New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec, err := c.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error {
		return nil
	}, fields...)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	return rec
}

func TestVerifyRecordAcceptsAnAuthenticRecord(t *testing.T) {
	key := make([]byte, 32)
	rec := appendOne(t, key, "login", "alice")
	if err := auditchain.VerifyRecord(key, rec); err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}
}

func TestVerifyRecordRefusesAForgedField(t *testing.T) {
	key := make([]byte, 32)
	rec := appendOne(t, key, "login", "alice")
	rec.Fields = []string{"login", "mallory"}
	if err := auditchain.VerifyRecord(key, rec); err == nil {
		t.Fatal("VerifyRecord accepted a rewritten field")
	}
}

func TestVerifyRecordRefusesAnotherKey(t *testing.T) {
	key := make([]byte, 32)
	other := make([]byte, 32)
	other[0] = 1
	rec := appendOne(t, key, "login", "alice")
	if err := auditchain.VerifyRecord(other, rec); err == nil {
		t.Fatal("VerifyRecord accepted a record under a different key")
	}
}

// The whole point: unlike Resume, this asks nothing about where the record sits.
func TestVerifyRecordSaysNothingAboutTailness(t *testing.T) {
	key := make([]byte, 32)
	c, err := auditchain.New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	persist := func(auditchain.Record, auditchain.Anchor) error { return nil }
	first, err := c.Append(context.Background(), persist, "login", "alice")
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := c.Append(context.Background(), persist, "logout", "alice"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// first is now in the middle. VerifyRecord still accepts it.
	if err := auditchain.VerifyRecord(key, first); err != nil {
		t.Fatalf("VerifyRecord on a mid-chain record: %v", err)
	}
	// Resume, given the same record and the chain's real anchor, refuses it.
	if _, err := auditchain.Resume(key, first, c.Anchor()); err == nil {
		t.Fatal("Resume accepted a mid-chain record as the tail")
	}
}

func TestVerifyRecordRefusesAShortKey(t *testing.T) {
	rec := appendOne(t, make([]byte, 32), "login", "alice")
	if err := auditchain.VerifyRecord(make([]byte, 31), rec); err == nil {
		t.Fatal("VerifyRecord accepted a 31-byte key")
	}
	if err := auditchain.VerifyRecord(nil, rec); !errors.Is(err, auditchain.ErrWeakKey) {
		t.Errorf("nil key gave %v, want ErrWeakKey", err)
	}
}
