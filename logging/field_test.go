package logging

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// cyclicErr is a test error type whose Unwrap() returns itself, for testing
// that Err() doesn't hang on cyclic chains.
type cyclicErr struct {
	msg string
}

func (e *cyclicErr) Error() string { return e.msg }
func (e *cyclicErr) Unwrap() error { return e }

func TestSanitizeReplacesControlCharacters(t *testing.T) {
	// Every one of these can forge a line or break a parser downstream.
	for _, tc := range []struct{ name, in, want string }{
		{"newline", "a\nb", "a�b"},
		{"carriage return", "a\rb", "a�b"},
		{"nul", "a\x00b", "a�b"},
		{"escape", "a\x1bb", "a�b"},
		{"delete", "a\x7fb", "a�b"},
		{"tab", "a\tb", "a�b"},
		{"invalid utf8", "a\xffb", "a�b"},
		{"c1 control: CSI", "ab", "a�b"},
		{"c1 control: NEL", "ab", "a�b"},
		{"c1 control: PAD, range floor", "ab", "a�b"},
		{"c1 control: APC, range ceiling", "ab", "a�b"},
		{"clean text is untouched", `a "quoted" ] \ b`, `a "quoted" ] \ b`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, truncated := sanitize(tc.in)
			if got != tc.want {
				t.Errorf("sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if truncated {
				t.Errorf("sanitize(%q) reported truncation", tc.in)
			}
		})
	}
}

func TestSanitizeCapsAtTheCeiling(t *testing.T) {
	// 253 payload bytes plus the 3-byte ellipsis is the 256-byte ceiling.
	const payload = maxValueBytes - len("…")

	fits := strings.Repeat("a", payload)
	if got, truncated := sanitize(fits); truncated || got != fits {
		t.Errorf("a %d-byte value was truncated", payload)
	}

	over := strings.Repeat("a", payload+1)
	got, truncated := sanitize(over)
	if !truncated {
		t.Fatal("a value past the budget was not reported as truncated")
	}
	if len(got) != maxValueBytes {
		t.Errorf("truncated value is %d bytes, want exactly %d", len(got), maxValueBytes)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated value %q does not end in the marker", got)
	}
}

func TestSanitizeTruncatesOnARuneBoundary(t *testing.T) {
	// Each rune is 3 bytes, so the budget does not divide evenly and the cut
	// must fall between runes rather than through one.
	got, truncated := sanitize(strings.Repeat("世", 200))
	if !truncated {
		t.Fatal("want truncation")
	}
	if strings.ContainsRune(got, '�') {
		t.Errorf("truncation split a rune: %q", got)
	}
	if len(got) > maxValueBytes {
		t.Errorf("truncated value is %d bytes, over the %d ceiling", len(got), maxValueBytes)
	}
}

func TestDeclareRefusesBadNames(t *testing.T) {
	for _, tc := range []struct{ name, key string }{
		{"reserved: audit key", "hash"},
		{"reserved: line key", "message"},
		{"reserved: single source", "request_id"},
		{"slog builtin: time", "time"},
		{"slog builtin: msg", "msg"},
		{"uppercase", "UserName"},
		{"leading digit", "1st_try"},
		{"hyphen", "user-id"},
		{"dot", "user.id"},
		{"empty", ""},
		{"already declared", "user_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("DeclareString(%q) did not panic", tc.key)
				}
			}()
			DeclareString(tc.key)
		})
	}
}

func TestDeclaredConstructorSanitizes(t *testing.T) {
	f := UserID("u_1\nfake")
	if got := f.val.v.String(); got != "u_1�fake" {
		t.Errorf("UserID kept a control character: %q", got)
	}
	if f.key != "user_id" {
		t.Errorf("key = %q, want user_id", f.key)
	}
}

func TestReservedKeysAreNotDeclared(t *testing.T) {
	// A reserved key that is also declared would have two sources and no rule
	// about which wins.
	for key := range reserved {
		if isDeclared(key) {
			t.Errorf("%q is both reserved and declared", key)
		}
	}
}

func TestErrDropsTheWrappingAndKeepsTheKind(t *testing.T) {
	// Wrapping is where paths, queries and tokens get added; the leaf is a
	// sentinel with constant text.
	wrapped := fmt.Errorf("opening /etc/kypassword/secret.key: %w", fs.ErrNotExist)

	kind := Err(wrapped)
	if got := kind.val.v.String(); got != fs.ErrNotExist.Error() {
		t.Errorf("Err = %q, want the leaf sentinel %q", got, fs.ErrNotExist.Error())
	}
	if strings.Contains(kind.val.v.String(), "secret.key") {
		t.Error("Err leaked the wrapped path")
	}
	if kind.key != "error_kind" {
		t.Errorf("key = %q, want error_kind", kind.key)
	}

	text := ErrText(wrapped)
	if !strings.Contains(text.val.v.String(), "secret.key") {
		t.Error("ErrText dropped the message it exists to carry")
	}
	if text.key != "error_text" {
		t.Errorf("key = %q, want error_text", text.key)
	}

	// errors.Join breaks the single-chain assumption: errors.Unwrap returns nil for it,
	// so a naive walk would stop at err.Error() — the concatenation of every joined
	// error's full text, wrapper included. Each branch must be unwrapped to its own leaf.
	joined := errors.Join(context.Canceled, fmt.Errorf("opening /etc/kypassword/secret.key: %w", fs.ErrNotExist))
	joinedKind := Err(joined)
	joinedGot := joinedKind.val.v.String()
	if strings.Contains(joinedGot, "secret.key") {
		t.Errorf("Err leaked the wrapped path through errors.Join: %q", joinedGot)
	}
	wantJoined := "context canceled�file does not exist" // \n between leaves, sanitized to U+FFFD
	if joinedGot != wantJoined {
		t.Errorf("Err(joined) = %q, want %q", joinedGot, wantJoined)
	}
	if joinedKind.key != "error_kind" {
		t.Errorf("key = %q, want error_kind", joinedKind.key)
	}
}

func TestErrOfNilContributesNothing(t *testing.T) {
	if got := Err(nil).attr(); !got.Equal(slog.Attr{}) {
		t.Errorf("Err(nil) = %v, want the empty attr", got)
	}
}

func TestErrBoundsUnwrapLoopOnCyclicChain(t *testing.T) {
	// A cyclic error chain would hang the unwrap loop without a depth bound.
	// Run Err() in a goroutine with a timeout to catch any hangs.
	result := make(chan Field, 1)
	cyclic := &cyclicErr{msg: "cyclic error"}
	go func() {
		result <- Err(cyclic)
	}()

	select {
	case f := <-result:
		// Expected: should return a Field with key "error_kind" and a string value.
		if f.key != "error_kind" {
			t.Errorf("key = %q, want error_kind", f.key)
		}
		// A cycle is exactly the budget running out, and what the walk holds then is a
		// wrapper: the marker, never its text.
		if got := f.val.v.String(); got != unwrapBudgetExceeded {
			t.Errorf("value = %q, want %q", got, unwrapBudgetExceeded)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Err() hung on cyclic error chain")
	}
}

// nilBranchJoinErr is a hand-written multi-error whose Unwrap() []error returns a nil
// element. errors.Join and fmt.Errorf's multi-%w never produce this shape, but errors.Is
// and errors.As both tolerate it from a caller's own type, and unwrapKind walks the same
// interface they do.
type nilBranchJoinErr struct{}

func (nilBranchJoinErr) Error() string   { return "nil branch join" }
func (nilBranchJoinErr) Unwrap() []error { return []error{context.Canceled, nil} }

func TestErrToleratesANilJoinBranch(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Err panicked on a nil join branch: %v", r)
		}
	}()
	got := Err(nilBranchJoinErr{})
	if got.key != "error_kind" {
		t.Errorf("key = %q, want error_kind", got.key)
	}
}

// The budget is shared across every branch of a joined error and each wrapped branch
// costs two steps, so a join of 50 wrapped errors exhausts it on the last branch, inside
// the 256-byte value cap. Past that point the walk
// used to return err.Error() of whatever it held -- an unwrapped wrapper, carrying exactly
// the path or query text Err exists to drop -- and with short sentinel leaves the joined
// value stays under the cap, so it reached the line. Batch operations that join per-item
// errors are the realistic trigger.
//
// Written first against the err.Error() fallback, where the marker text reached the line.
func TestErrLeaksNoWrapperTextPastTheUnwrapBudget(t *testing.T) {
	const secret = "SECRET_PATH_IN_WRAPPER"
	// One-byte leaves: the join separator sanitises to three bytes, so longer leaves push
	// the exhaustion point past the value cap and the marker out of sight.
	leaf := errors.New("x")
	branches := make([]error, 50)
	for i := range branches {
		branches[i] = fmt.Errorf("open /var/%s/%d: %w", secret, i, leaf)
	}
	got := Err(errors.Join(branches...)).val.v.String()
	if strings.Contains(got, secret) {
		t.Fatalf("wrapper text reached the line once the unwrap budget ran out: %q", got)
	}
	if !strings.Contains(got, unwrapBudgetExceeded) {
		t.Fatalf("budget exhaustion is not marked: %q", got)
	}
}
