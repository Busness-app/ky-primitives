// Package logging is the suite's log line builder.
//
// Products write JSON lines to stderr; a collector agent ships them onward. This package
// opens no socket, holds no buffer and rotates no file, because an agent survives the
// process dying and a library buffer does not.
//
// What it does own is what may appear on a line. Values are typed and sanitized, so a
// field cannot forge a line the way a bare newline in a value does. Keys must be
// declared, so a secret cannot ride along under a name nobody anticipated — the suite's
// two existing redaction schemes are a key-name denylist, which fails silently, and a
// runtime allowlist, which this borrows and makes stricter.
package logging

import (
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// maxValueBytes is the hard ceiling on any one rendered value, marker included.
//
// The cap bounds the blast radius of a single field: a value that grows without limit
// takes the rest of the line with it, and a line a collector rejects is a line nobody
// reads. The budget for the payload is the ceiling less the marker, which keeps the
// arithmetic small enough to be obviously right.
const maxValueBytes = 256

const truncMarker = "…"

// sanitize makes a string safe to place on a line: no control characters, no invalid
// UTF-8, never past the ceiling. It reports whether it had to cut.
//
// Replacing control characters is what makes log injection impossible, and it happens
// here — on the value — rather than in a renderer, so no later output format can skip it.
func sanitize(s string) (string, bool) {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == utf8.RuneError {
			r = '�'
		}
		if b.Len()+utf8.RuneLen(r) > maxValueBytes-len(truncMarker) {
			return b.String() + truncMarker, true
		}
		b.WriteRune(r)
	}
	return b.String(), false
}

// fieldValue carries a rendered value plus whether it was cut. Its type is unexported,
// which is how the handler tells a value this package produced from one that arrived as a
// raw slog attribute.
type fieldValue struct {
	v         slog.Value
	truncated bool
}

// Field is one key and value on a log line. Its members are unexported, so the only
// fields that exist are ones a constructor in this package produced.
type Field struct {
	key string
	val fieldValue
}

// attr renders the field for slog. The zero Field renders as an empty attr, which the
// handler skips — that is how Err(nil) contributes nothing.
func (f Field) attr() slog.Attr {
	if f.key == "" {
		return slog.Attr{}
	}
	return slog.Any(f.key, f.val)
}

// reserved keys are set by the handler and may not be declared.
//
// The line keys would be duplicated; event and request_id each have exactly one source,
// so a field of the same name could contradict them; seq, prev, hash and fields are
// the shape cmd/kyauditverify parses, so a field colliding with one would corrupt a chain
// record on its way through the stream; and audit_fields_mismatch is Audit's own warning
// that the flat keys on a line disagree with what the record's Fields digested — a field
// of that name could claim a divergent line agrees after all.
var reserved = map[string]bool{
	"timestamp": true, "level": true, "message": true, "app": true,
	"event": true, "request_id": true, "severity": true, "facility": true,
	"dropped_fields": true, "truncated_fields": true,
	"seq": true, "prev": true, "hash": true, "fields": true,
	"audit_fields_mismatch": true,
}

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

var (
	declaredMu sync.RWMutex
	declared   = map[string]bool{}
)

// register admits a key to the vocabulary, or panics.
//
// Panicking is the right failure: declarations run at package initialisation, so a bad
// one fails at startup in every environment, before a single line is written. Returning
// an error would put the check somewhere a product could ignore it.
func register(name string) {
	if reserved[name] {
		panic("logging: " + name + " is reserved and set by the handler")
	}
	if !keyPattern.MatchString(name) {
		panic("logging: field name " + name + " must match [a-z][a-z0-9_]*")
	}
	declaredMu.Lock()
	defer declaredMu.Unlock()
	if declared[name] {
		panic("logging: field " + name + " is already declared")
	}
	declared[name] = true
}

func isDeclared(key string) bool {
	declaredMu.RLock()
	defer declaredMu.RUnlock()
	return declared[key]
}

func isReserved(key string) bool { return reserved[key] }

// DeclareString admits a string-valued key and returns its constructor. Call it once, at
// package level, in the product that needs the key.
func DeclareString(name string) func(string) Field {
	register(name)
	return func(v string) Field {
		s, truncated := sanitize(v)
		return Field{key: name, val: fieldValue{v: slog.StringValue(s), truncated: truncated}}
	}
}

// DeclareInt admits an integer-valued key and returns its constructor.
func DeclareInt(name string) func(int64) Field {
	register(name)
	return func(v int64) Field {
		return Field{key: name, val: fieldValue{v: slog.Int64Value(v)}}
	}
}

// DeclareBool admits a boolean-valued key and returns its constructor.
func DeclareBool(name string) func(bool) Field {
	register(name)
	return func(v bool) Field {
		return Field{key: name, val: fieldValue{v: slog.BoolValue(v)}}
	}
}

// DeclareTime admits a time-valued key and returns its constructor.
func DeclareTime(name string) func(time.Time) Field {
	register(name)
	return func(v time.Time) Field {
		return Field{key: name, val: fieldValue{v: slog.TimeValue(v.UTC())}}
	}
}

// The shared vocabulary. The first nineteen are kynotes-server's allowlist, which is the
// only field allowlist in the suite and was chosen against a real product; the rest are
// what the other eight log today. Two of kynotes' keys are absent because they are
// reserved here: event comes from the event constant and request_id from the context.
var (
	Route        = DeclareString("route")
	Method       = DeclareString("method")
	Status       = DeclareInt("status")
	DurationMS   = DeclareInt("duration_ms")
	Bytes        = DeclareInt("bytes")
	Outcome      = DeclareString("outcome")
	UserID       = DeclareString("user_id")
	DeviceID     = DeclareString("device_id")
	ContainerID  = DeclareString("container_id")
	ObjectID     = DeclareString("object_id")
	AttachmentID = DeclareString("attachment_id")
	UploadID     = DeclareString("upload_id")
	SessionID    = DeclareString("session_id")
	AuditID      = DeclareString("audit_id")
	Count        = DeclareInt("count")
	ReasonCode   = DeclareString("reason_code")
	RetryAfterS  = DeclareInt("retry_after_s")
	Version      = DeclareString("version")
	ErrorKind    = DeclareString("error_kind")

	ErrorText  = DeclareString("error_text")
	RemoteIP   = DeclareString("remote_ip")
	UserAgent  = DeclareString("user_agent")
	Action     = DeclareString("action")
	TargetID   = DeclareString("target_id")
	ActorID    = DeclareString("actor_id")
	CapsuleID  = DeclareString("capsule_id")
	ShareIndex = DeclareInt("share_index")
	Zone       = DeclareString("zone")
	QName      = DeclareString("qname")
)

// Err reports what kind of error occurred without its message.
//
// It unwraps to the deepest error and emits that one's text, which for a sentinel such as
// fs.ErrNotExist or auditchain.ErrBrokenChain is a constant. Wrapping is where the
// dynamic content gets added — filesystem paths, query text, occasionally a token in a
// URL — so dropping the wrappers drops the leak. This is not airtight: a leaf built by
// fmt.Errorf with no %w carries whatever the caller put in it. It removes the accidental
// case, which is the one that happens.
//
// errors.Join (and fmt.Errorf with multiple %w verbs) does not fit the single-chain walk:
// errors.Unwrap returns nil for one, so a naive loop would stop at err.Error() and emit
// every joined error's full text — the wrapper this function exists to drop. Instead each
// joined branch is unwrapped to its own leaf and the leaf kinds are joined, so a joined
// error leaks no more than a single wrapped one does.
//
// The unwrap walk is bounded at 100 steps total, shared across every branch of a joined
// error, to guard against a cyclic error chain hanging the goroutine. Real wrap chains are
// under ten deep, so 100 is a guard rather than a policy.
func Err(err error) Field {
	if err == nil {
		return Field{}
	}
	budget := 100
	return ErrorKind(unwrapKind(err, &budget))
}

// unwrapKind walks err to its deepest leaf's text, recursing into each branch of a joined
// error and joining their leaf kinds with newlines. budget is shared across the whole
// walk — every branch of every join draws from the same pool — so it bounds the total work
// rather than resetting per branch.
func unwrapKind(err error, budget *int) string {
	for *budget > 0 {
		*budget--
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			branches := joined.Unwrap()
			kinds := make([]string, len(branches))
			for i, b := range branches {
				kinds[i] = unwrapKind(b, budget)
			}
			return strings.Join(kinds, "\n")
		}
		next := errors.Unwrap(err)
		if next == nil {
			return err.Error()
		}
		err = next
	}
	// Hit the depth bound; return what we're holding rather than looping forever.
	return err.Error()
}

// ErrText emits the full error message, sanitized and capped. Use it when the message is
// needed and you have decided it is safe to store centrally. It greps.
func ErrText(err error) Field {
	if err == nil {
		return Field{}
	}
	return ErrorText(err.Error())
}
