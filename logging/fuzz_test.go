package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzFieldValuesCannotForgeALine drives random input through both channels this package
// bounds: the typed field API, and the raw message a product on Handler() still controls
// directly.
//
// Most of what it checks already holds through slog's own JSON encoding, sanitize or not:
// slog escapes every byte under 0x20 and replaces invalid UTF-8 on its own, so a bare
// newline or a bad byte was never going to split a line by itself. Two things are actually
// pinned here. DEL (0x7f) is in slog's safeSet and ships unescaped, so keeping it off the
// line is sanitize's job, not the encoder's. And cutting a value at the maxValueBytes
// budget has to land on a rune boundary, never splitting one into invalid UTF-8. The rest
// of what is asserted below — one line per call, no forged seq key — are cheap regression
// guards on top, not properties unique to this package.
func FuzzFieldValuesCannotForgeALine(f *testing.F) {
	f.Add("plain")
	f.Add("a\nb")
	f.Add("\x00\x1b[31m")
	f.Add(`{"seq":1,"prev":"x","hash":"y","fields":[]}`)
	f.Add(strings.Repeat("世", 500))
	f.Add("\xff\xfe")

	f.Fuzz(func(t *testing.T, v string) {
		var buf bytes.Buffer
		lg, err := New(Config{App: "kyfuzz", Level: slog.LevelDebug, Out: &buf})
		if err != nil {
			t.Fatal(err)
		}
		lg.Log(context.Background(), Started, Version(v), UserID(v), Action(v))
		m := checkLine(t, buf.String())
		for _, key := range []string{"version", "user_id", "action"} {
			checkValue(t, m, key)
		}
		// A field value must never be able to inject an audit record.
		if _, ok := m["seq"]; ok {
			t.Fatalf("a field value produced a seq key: %v", m)
		}

		// The raw message on the Handler() path is caller-controlled free text this
		// package does not vocabulary-bound; it still has to land safely.
		var msgBuf bytes.Buffer
		mlg, err := New(Config{App: "kyfuzz", Level: slog.LevelDebug, Out: &msgBuf})
		if err != nil {
			t.Fatal(err)
		}
		slog.New(mlg.Handler()).Info(v)
		checkValue(t, checkLine(t, msgBuf.String()), "message")
	})
}

// checkLine asserts one call produced one parseable JSON line and returns it decoded.
func checkLine(t *testing.T, out string) map[string]any {
	t.Helper()
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("one call produced %d newlines: %q", n, out)
	}
	body := strings.TrimSuffix(out, "\n")
	for _, r := range body {
		// sanitize is what keeps a raw control character off the line; this loop is
		// the one place that would notice if it ever stopped. The C1 range (0x80-0x9F)
		// is in here alongside C0 and DEL because slog's JSON string encoder does not
		// escape it — a regression in sanitize's C1 handling would otherwise put a raw
		// C1 byte on the line with nothing here to catch it.
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("a raw control character reached the line: %q", body)
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("line is not JSON: %v\n%q", err, body)
	}
	return m
}

// checkValue asserts a rendered value round-trips as a bounded, valid string.
func checkValue(t *testing.T, m map[string]any, key string) {
	t.Helper()
	s, ok := m[key].(string)
	if !ok {
		t.Fatalf("%s is %T, want a string", key, m[key])
	}
	if len(s) > maxValueBytes {
		t.Fatalf("%s is %d bytes, over the %d ceiling", key, len(s), maxValueBytes)
	}
	if !utf8.ValidString(s) {
		t.Fatalf("%s is not valid UTF-8: %q", key, s)
	}
}
