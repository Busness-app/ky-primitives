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

// FuzzFieldValuesCannotForgeALine is the package's primary security property under
// random input: whatever a value contains, one call produces one parseable line.
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

		out := buf.String()
		if n := strings.Count(out, "\n"); n != 1 {
			t.Fatalf("one call produced %d newlines: %q", n, out)
		}
		body := strings.TrimSuffix(out, "\n")
		for _, r := range body {
			if r < 0x20 && r != '\t' || r == 0x7f {
				t.Fatalf("a raw control character reached the line: %q", body)
			}
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("line is not JSON: %v\n%q", err, body)
		}
		for _, key := range []string{"version", "user_id", "action"} {
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
		// A value must never be able to inject an audit record.
		if _, ok := m["seq"]; ok {
			t.Fatalf("a field value produced a seq key: %q", body)
		}
	})
}
