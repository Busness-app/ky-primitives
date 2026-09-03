package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// newTestLogger returns a logger writing into a buffer the caller can read back.
func newTestLogger(t *testing.T, level slog.Level) (*Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	lg, err := New(Config{App: "kytest", Level: level, Out: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return lg, &buf
}

// oneLine decodes the single JSON object the buffer must hold.
func oneLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 line, got %d: %q", len(lines), buf.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("line is not JSON: %v\n%s", err, lines[0])
	}
	return m
}

func TestLineCarriesTheSuiteKeys(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)
	lg.Log(context.Background(), Started, Version("v0.2.0"))

	m := oneLine(t, buf)
	for _, key := range []string{"timestamp", "level", "message", "app", "event", "severity", "facility"} {
		if _, ok := m[key]; !ok {
			t.Errorf("line is missing %q: %v", key, m)
		}
	}
	// slog's own key names must not survive.
	for _, key := range []string{"time", "msg"} {
		if _, ok := m[key]; ok {
			t.Errorf("line still carries slog's %q", key)
		}
	}
	if m["app"] != "kytest" {
		t.Errorf("app = %v, want kytest", m["app"])
	}
	if m["event"] != "started" {
		t.Errorf("event = %v, want started", m["event"])
	}
	if m["message"] != "service started" {
		t.Errorf("message = %v, want the event's constant", m["message"])
	}
	if m["version"] != "v0.2.0" {
		t.Errorf("version = %v, want v0.2.0", m["version"])
	}
	if m["severity"] != float64(6) {
		t.Errorf("severity = %v, want 6", m["severity"])
	}
	if m["facility"] != float64(facilityLocal0) {
		t.Errorf("facility = %v, want %d", m["facility"], facilityLocal0)
	}
}

func TestSecurityUsesTheAuthprivFacility(t *testing.T) {
	// A collector must be able to route the security stream to different
	// retention without reading the payload.
	lg, buf := newTestLogger(t, slog.LevelInfo)
	lg.Security(context.Background(), AuthFailed, UserID("u_1"))

	m := oneLine(t, buf)
	if m["facility"] != float64(facilityAuthpriv) {
		t.Errorf("facility = %v, want %d", m["facility"], facilityAuthpriv)
	}
	if m["severity"] != float64(4) {
		t.Errorf("severity = %v, want 4 for a warning", m["severity"])
	}
}

func TestLevelFiltersBelowTheThreshold(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelWarn)
	lg.Log(context.Background(), Started)
	if buf.Len() != 0 {
		t.Errorf("an info event was written at warn level: %q", buf.String())
	}
	lg.Security(context.Background(), AuthFailed)
	if buf.Len() == 0 {
		t.Error("a warn event was filtered at warn level")
	}
}

func TestRequestIDComesFromTheContext(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)
	ctx := WithRequestID(context.Background(), "req_9f2a\n71c4")
	lg.Log(ctx, Started)

	m := oneLine(t, buf)
	if m["request_id"] != "req_9f2a�71c4" {
		t.Errorf("request_id = %v, want the sanitized id", m["request_id"])
	}
}

func TestNewRefusesAnEmptyApp(t *testing.T) {
	// An unattributed line in a central store is nearly useless.
	if _, err := New(Config{Level: slog.LevelInfo, Out: &bytes.Buffer{}}); err == nil {
		t.Error("New accepted an empty App")
	}
}

func TestRawSlogAttrsAreFilteredAndCounted(t *testing.T) {
	// The migration path: a product installs the handler and keeps its existing
	// call sites. What it loses must show on the line, not vanish.
	lg, buf := newTestLogger(t, slog.LevelInfo)
	sl := slog.New(lg.Handler())
	sl.Info("legacy call site",
		slog.String("user_id", "u_1"),         // declared: kept
		slog.String("argon2_hash", "$argon2"), // undeclared: dropped
		slog.String("password", "hunter2"),    // undeclared: dropped
	)

	m := oneLine(t, buf)
	if m["user_id"] != "u_1" {
		t.Errorf("a declared key was not kept: %v", m)
	}
	if _, ok := m["argon2_hash"]; ok {
		t.Error("an undeclared key reached the line")
	}
	if m["dropped_fields"] != float64(2) {
		t.Errorf("dropped_fields = %v, want 2", m["dropped_fields"])
	}
	if strings.Contains(buf.String(), "hunter2") {
		t.Error("a dropped value survived in the line")
	}
}

func TestRawSlogCannotSetReservedKeys(t *testing.T) {
	// seq, prev, hash and fields are the shape kyauditverify parses. A raw call
	// site must not be able to forge one into the stream.
	lg, buf := newTestLogger(t, slog.LevelInfo)
	sl := slog.New(lg.Handler())
	sl.Info("forgery attempt",
		slog.Int64("seq", 99),
		slog.String("prev", "deadbeef"),
		slog.String("hash", "deadbeef"),
		slog.String("app", "not-kytest"),
		slog.String("event", "auth_succeeded"),
	)

	m := oneLine(t, buf)
	if _, ok := m["seq"]; ok {
		t.Error("a raw attribute set seq")
	}
	if _, ok := m["hash"]; ok {
		t.Error("a raw attribute set hash")
	}
	if m["app"] != "kytest" {
		t.Errorf("a raw attribute overrode app: %v", m["app"])
	}
	if _, ok := m["event"]; ok {
		t.Error("a raw attribute set event")
	}
	if m["dropped_fields"] != float64(5) {
		t.Errorf("dropped_fields = %v, want 5", m["dropped_fields"])
	}
}

func TestTruncationIsCounted(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)
	lg.Log(context.Background(), Started, Version(strings.Repeat("v", 1000)))

	m := oneLine(t, buf)
	if m["truncated_fields"] != float64(1) {
		t.Errorf("truncated_fields = %v, want 1", m["truncated_fields"])
	}
	if got := m["version"].(string); len(got) != maxValueBytes {
		t.Errorf("version is %d bytes, want %d", len(got), maxValueBytes)
	}
}

func TestGroupsDoNotNestKeys(t *testing.T) {
	// A nested line cannot be unmarshalled into an auditchain.Record.
	lg, buf := newTestLogger(t, slog.LevelInfo)
	sl := slog.New(lg.Handler()).WithGroup("http")
	sl.Info("grouped", slog.String("user_id", "u_1"))

	m := oneLine(t, buf)
	if _, ok := m["http"]; ok {
		t.Error("a group nested the line")
	}
	if m["user_id"] != "u_1" {
		t.Errorf("user_id = %v, want u_1 at the top level", m["user_id"])
	}
}

// TestRawIntKeepsItsJSONType is the controller ruling on the default arm: a
// declared int key arriving through raw slog must reach the line as a JSON
// number, matching what the typed API produces for the same key. Stringifying
// it would make the same field's JSON type depend on which API wrote the line.
func TestRawIntKeepsItsJSONType(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)
	sl := slog.New(lg.Handler())
	sl.Info("legacy call site", slog.Int64("status", 200))

	m := oneLine(t, buf)
	if _, isString := m["status"].(string); isString {
		t.Errorf("status arrived as a JSON string: %v", m["status"])
	}
	if m["status"] != float64(200) {
		t.Errorf("status = %v, want the number 200", m["status"])
	}
}

// TestRawAnyUnderADeclaredKeyIsDropped is the other half of the ruling: a
// declared key does not make an arbitrary Go value safe to render. slog.Any
// carrying a struct must be dropped and counted, not stringified onto the line.
func TestRawAnyUnderADeclaredKeyIsDropped(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)
	sl := slog.New(lg.Handler())
	type payload struct{ Secret string }
	sl.Info("legacy call site", slog.Any("user_id", payload{Secret: "shhh"}))

	m := oneLine(t, buf)
	if _, ok := m["user_id"]; ok {
		t.Errorf("an Any value under a declared key reached the line: %v", m)
	}
	if m["dropped_fields"] != float64(1) {
		t.Errorf("dropped_fields = %v, want 1", m["dropped_fields"])
	}
	if strings.Contains(buf.String(), "shhh") {
		t.Error("the struct's field survived in the line")
	}
}

// TestConcurrentLogAndSecurityDoNotRace pins the fix for a review finding: New used to
// build two slog.NewJSONHandlers over the same io.Writer, and each JSONHandler owns its
// own mutex. The two streams serialized against different locks and raced on Out.Write.
// This is ordinary usage — a request handler logging an ops line while auth middleware
// logs a security line for the same request — so it needs no special trigger beyond
// concurrent calls under -race.
func TestConcurrentLogAndSecurityDoNotRace(t *testing.T) {
	lg, _ := newTestLogger(t, slog.LevelInfo)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			lg.Log(context.Background(), Started)
		}()
		go func() {
			defer wg.Done()
			lg.Security(context.Background(), AuthFailed)
		}()
	}
	wg.Wait()
}

// TestRecordMessageIsSanitized pins the fix for a review finding: Handle passed
// r.Message straight into the output record. On the typed API the message is always an
// Event's constant, so this only bites a product's raw slog call sites — exactly the
// path Handler() exists to support — where the message is arbitrary caller data.
func TestRecordMessageIsSanitized(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)
	sl := slog.New(lg.Handler())
	sl.Info("bad\nmessage" + strings.Repeat("M", 4000))

	m := oneLine(t, buf)
	msg, ok := m["message"].(string)
	if !ok {
		t.Fatalf("message is not a string: %v", m["message"])
	}
	if strings.Contains(msg, "\n") {
		t.Error("message still carries a raw newline")
	}
	if len(msg) > maxValueBytes {
		t.Errorf("message is %d bytes, want at most %d", len(msg), maxValueBytes)
	}
	if m["truncated_fields"] != float64(1) {
		t.Errorf("truncated_fields = %v, want 1 for an over-long message", m["truncated_fields"])
	}
}

// TestWithAttrsRefusesUndeclaredAndReservedKeys pins WithAttrs, the one place a
// divergent second filter could be introduced with nothing failing. It must apply the
// same rules Handle applies to a raw call site's attrs.
func TestWithAttrsRefusesUndeclaredAndReservedKeys(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)
	sl := slog.New(lg.Handler()).With(
		slog.String("user_id", "u_1"),         // declared: kept
		slog.String("argon2_hash", "$argon2"), // undeclared: dropped
		slog.Int64("seq", 99),                 // reserved: dropped
	)
	sl.Info("derived line")

	m := oneLine(t, buf)
	if m["app"] != "kytest" {
		t.Errorf("app = %v, want kytest to survive on a derived handler", m["app"])
	}
	if m["facility"] != float64(facilityLocal0) {
		t.Errorf("facility = %v, want %d to survive on a derived handler", m["facility"], facilityLocal0)
	}
	if m["user_id"] != "u_1" {
		t.Errorf("a declared key attached via With was not kept: %v", m)
	}
	if _, ok := m["argon2_hash"]; ok {
		t.Error("an undeclared key attached via With reached the line")
	}
	if _, ok := m["seq"]; ok {
		t.Error("a reserved key attached via With reached the line")
	}
	if m["dropped_fields"] != float64(2) {
		t.Errorf("dropped_fields = %v, want 2", m["dropped_fields"])
	}
}

// TestWithAttrsCountsTruncation pins the fix for a review finding: WithAttrs discarded
// filter's dropped and truncated counts, so a value cut at .With() time went uncounted —
// contradicting the package's own promise that a loss shows up on the line.
func TestWithAttrsCountsTruncation(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)
	sl := slog.New(lg.Handler()).With(slog.String("user_id", strings.Repeat("u", 1000)))
	sl.Info("derived line")

	m := oneLine(t, buf)
	if m["truncated_fields"] != float64(1) {
		t.Errorf("truncated_fields = %v, want 1 for a value truncated at With time", m["truncated_fields"])
	}
}

// TestRequestIDTruncationIsCounted pins the same omission as above, found in the
// request-id path: an over-long request ID truncated silently.
func TestRequestIDTruncationIsCounted(t *testing.T) {
	lg, buf := newTestLogger(t, slog.LevelInfo)
	ctx := WithRequestID(context.Background(), strings.Repeat("r", 1000))
	lg.Log(ctx, Started)

	m := oneLine(t, buf)
	if m["truncated_fields"] != float64(1) {
		t.Errorf("truncated_fields = %v, want 1 for an over-long request id", m["truncated_fields"])
	}
	if got := m["request_id"].(string); len(got) != maxValueBytes {
		t.Errorf("request_id is %d bytes, want %d", len(got), maxValueBytes)
	}
}

func TestFromEnv(t *testing.T) {
	cases := []struct {
		name    string
		env     string
		wantErr bool
		wantNil bool // unset: Config's zero value, meaning Info once New sees it
		want    slog.Level
	}{
		{name: "unset reads as info", env: "", wantNil: true},
		{name: "valid lowercase level", env: "warn", want: slog.LevelWarn},
		{name: "invalid level errors", env: "nope", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("KY_LOG_LEVEL", c.env)
			cfg, err := FromEnv()
			if c.wantErr {
				if err == nil {
					t.Fatal("FromEnv accepted an invalid level")
				}
				return
			}
			if err != nil {
				t.Fatalf("FromEnv: %v", err)
			}
			if c.wantNil {
				if cfg.Level != nil {
					t.Errorf("Level = %v, want nil", cfg.Level)
				}
				return
			}
			if cfg.Level != c.want {
				t.Errorf("Level = %v, want %v", cfg.Level, c.want)
			}
		})
	}
}

// TestConfigLevelVarFiltersAndCanChangeAtRuntime pins the fix for a review finding:
// Config.Level was slog.Level, so a product could not install a *slog.LevelVar and adjust
// verbosity at runtime (e.g. on SIGHUP) without a breaking change to this struct later.
func TestConfigLevelVarFiltersAndCanChangeAtRuntime(t *testing.T) {
	var lv slog.LevelVar
	lv.Set(slog.LevelWarn)
	var buf bytes.Buffer
	lg, err := New(Config{App: "kytest", Level: &lv, Out: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	lg.Log(context.Background(), Started)
	if buf.Len() != 0 {
		t.Fatalf("an info event was written while the LevelVar held warn: %q", buf.String())
	}

	lv.Set(slog.LevelInfo)
	lg.Log(context.Background(), Started)
	if buf.Len() == 0 {
		t.Error("lowering the LevelVar at runtime did not unblock an info event")
	}
}
