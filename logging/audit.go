package logging

import (
	"context"
	"log/slog"
	"strconv"

	"github.com/Busness-app/ky-primitives/auditchain"
)

// auditValue carries a chain record to the handler. Its type is unexported, so code
// outside this package cannot forge seq, prev, hash and fields into the stream — which
// matters because cmd/kyauditverify will parse whatever carries them.
type auditValue struct{ rec auditchain.Record }

// attrs flattens the record onto the line. Flat, not nested, because kyauditverify
// unmarshals the whole line into an auditchain.Record and Go's decoder ignores the keys
// it does not know.
func (a auditValue) attrs() []slog.Attr {
	return []slog.Attr{
		slog.Uint64("seq", a.rec.Seq),
		slog.String("prev", a.rec.Prev),
		slog.String("hash", a.rec.Hash),
		slog.Any("fields", a.rec.Fields),
	}
}

// AuditFields renders declared fields as the canonical key=value strings a chain
// digests. Order is the argument order, and the digest depends on it.
//
// Building the chain's fields and the line's fields from the same values is what stops
// the two disagreeing: the record is what is authenticated, the flat keys are what the
// collector indexes, and a test asserts they match.
func AuditFields(fs ...Field) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		if f.key == "" {
			continue
		}
		out = append(out, f.key+"="+renderValue(f.val.v))
	}
	return out
}

// renderValue is the one spelling of a value for the chain. slog.Value.String would
// render a time in a format that depends on the value's kind, so times are pinned here.
func renderValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindTime:
		return v.Time().UTC().Format("2006-01-02T15:04:05.000000000Z")
	case slog.KindInt64:
		return strconv.FormatInt(v.Int64(), 10)
	case slog.KindBool:
		return strconv.FormatBool(v.Bool())
	default:
		return v.String()
	}
}

// Audit records a chain record on the authpriv facility, alongside the same values as
// flat keys.
//
// The record's storage stays with the product: auditchain deliberately owns none, and a
// tamper-evident chain that exists only on a machine the attacker may also own is not
// evidence. This ships a copy; the product keeps writing its local chained file.
func (l *Logger) Audit(ctx context.Context, ev Event, rec auditchain.Record, fs ...Field) {
	l.emit(ctx, l.sec, ev, []slog.Attr{slog.Any("audit", auditValue{rec: rec})}, fs)
}
