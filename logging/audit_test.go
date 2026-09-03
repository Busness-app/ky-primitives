package logging

import (
	"bufio"
	"context"
	"encoding/json"
	"iter"
	"log/slog"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/auditchain"
)

func TestAuditFieldsRendersCanonicalPairs(t *testing.T) {
	got := AuditFields(UserID("u_1"), Action("share_redeem"), ShareIndex(7))
	want := []string{"user_id=u_1", "action=share_redeem", "share_index=7"}
	if len(got) != len(want) {
		t.Fatalf("got %d fields, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAuditFieldsSanitizes(t *testing.T) {
	// A newline here would forge a record inside the digested field list.
	got := AuditFields(UserID("u_1\nuser_id=u_2"))
	if strings.ContainsAny(got[0], "\n\r") {
		t.Errorf("AuditFields kept a control character: %q", got[0])
	}
}

func TestAuditLineAgreesWithTheDigestedFields(t *testing.T) {
	// The two must carry the same values: one is what the digest covers, the
	// other is what the collector indexes.
	lg, buf := newTestLogger(t, slog.LevelInfo)

	chain, err := auditchain.New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	fields := AuditFields(UserID("u_1"), Action("share_redeem"))
	rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fields...)
	if err != nil {
		t.Fatal(err)
	}
	lg.Audit(context.Background(), ShareRedeemed, rec, UserID("u_1"), Action("share_redeem"))

	m := oneLine(t, buf)
	raw, ok := m["fields"].([]any)
	if !ok {
		t.Fatalf("fields is %T, want an array: %v", m["fields"], m)
	}
	if len(raw) != 2 || raw[0] != "user_id=u_1" || raw[1] != "action=share_redeem" {
		t.Errorf("fields = %v, want the digested pairs", raw)
	}
	if m["user_id"] != "u_1" {
		t.Errorf("flat user_id = %v, does not agree with the digested field", m["user_id"])
	}
	if m["action"] != "share_redeem" {
		t.Errorf("flat action = %v, does not agree with the digested field", m["action"])
	}
}

// testKey is a fixed 32-byte chain key. Test data, never a real key.
func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// records mirrors the iterator in cmd/kyauditverify: one record per line,
// reporting a malformed line rather than ending the walk early.
func records(r *strings.Reader) iter.Seq2[auditchain.Record, error] {
	return func(yield func(auditchain.Record, error) bool) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var rec auditchain.Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				yield(auditchain.Record{}, err)
				return
			}
			if !yield(rec, nil) {
				return
			}
		}
		if err := sc.Err(); err != nil {
			yield(auditchain.Record{}, err)
		}
	}
}

func TestShippedLinesVerifyAsAChain(t *testing.T) {
	// The whole point of the flat shape: cmd/kyauditverify reads the collector's
	// export with no change to that command.
	lg, buf := newTestLogger(t, slog.LevelInfo)
	key := testKey()

	chain, err := auditchain.New(key)
	if err != nil {
		t.Fatal(err)
	}
	for i, user := range []string{"u_1", "u_2", "u_3"} {
		fields := AuditFields(UserID(user), Count(int64(i)))
		rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fields...)
		if err != nil {
			t.Fatal(err)
		}
		lg.Audit(context.Background(), ShareRedeemed, rec, UserID(user), Count(int64(i)))
	}
	anchor := chain.Anchor()

	shipped := buf.String()
	if err := auditchain.VerifyStream(key, records(strings.NewReader(shipped)), anchor); err != nil {
		t.Fatalf("shipped lines do not verify: %v\n%s", err, shipped)
	}
}

func TestATamperedShippedLineFailsVerification(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)
	key := testKey()

	chain, err := auditchain.New(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"u_1", "u_2"} {
		fields := AuditFields(UserID(user))
		rec, err := chain.Append(context.Background(), func(auditchain.Record, auditchain.Anchor) error { return nil }, fields...)
		if err != nil {
			t.Fatal(err)
		}
		lg.Audit(context.Background(), ShareRedeemed, rec, UserID(user))
	}
	anchor := chain.Anchor()

	tampered := strings.Replace(buf.String(), "user_id=u_2", "user_id=u_9", 1)
	if tampered == buf.String() {
		t.Fatal("the test did not actually change a digested field")
	}
	if err := auditchain.VerifyStream(key, records(strings.NewReader(tampered)), anchor); err == nil {
		t.Error("a tampered line verified")
	}
}
