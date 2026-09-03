package logging

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
)

// RFC 5424 facilities. Ordinary lines are local0; security and audit lines are authpriv,
// so a collector can route the security stream to different retention without inspecting
// payloads.
const (
	facilityLocal0   int64 = 16
	facilityAuthpriv int64 = 10
)

// Config is everything the logger needs. There is no format field, because there is one
// format: JSON lines. A syslog renderer on stderr would duplicate a frame the collector
// agent supplies for us.
type Config struct {
	App   string       // required; identifies the product on every line
	Level slog.Leveler // default is slog.LevelInfo when nil, the zero value; a *slog.LevelVar works
	Out   io.Writer    // default os.Stderr
}

// FromEnv reads KY_LOG_LEVEL. App and Out are still the caller's to set, so configuration
// stays visible at the call site rather than hiding in the library.
//
// It returns an error rather than falling back, because a misspelled level that silently
// means info is how a product ends up logging nothing useful during the incident it was
// turned up for.
func FromEnv() (Config, error) {
	var cfg Config
	raw, ok := os.LookupEnv("KY_LOG_LEVEL")
	if !ok || raw == "" {
		return cfg, nil
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToUpper(raw))); err != nil {
		return Config{}, errors.New("logging: KY_LOG_LEVEL is not a level: " + raw)
	}
	cfg.Level = lvl
	return cfg, nil
}

// Logger writes the suite's log lines. It holds two slog loggers because facility is
// constant per handler, which keeps it out of reach of a raw slog attribute.
type Logger struct {
	ops *slog.Logger
	sec *slog.Logger
}

// New builds a logger. It fails on an empty App.
func New(cfg Config) (*Logger, error) {
	if !keyPattern.MatchString(strings.ReplaceAll(cfg.App, "-", "_")) {
		return nil, errors.New("logging: App must match [a-z][a-z0-9_-]*, got " + cfg.App)
	}
	out := cfg.Out
	if out == nil {
		out = os.Stderr
	}
	// One JSONHandler, shared by both facilities. slog.NewJSONHandler allocates its own
	// mutex; two of them writing to the same Out would serialize against different
	// locks and race on Out.Write the moment a product logs an ops line and a security
	// line concurrently, which is ordinary request-handler usage.
	inner := slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level:       cfg.Level,
		ReplaceAttr: renameSlogKeys,
	})
	return &Logger{
		ops: slog.New(&handler{inner: inner, app: cfg.App, facility: facilityLocal0}),
		sec: slog.New(&handler{inner: inner, app: cfg.App, facility: facilityAuthpriv}),
	}, nil
}

// Handler returns the handler as a slog.Handler, for a product mid-migration to install
// with slog.SetDefault. Attributes outside the vocabulary are dropped and counted rather
// than emitted, so the loss shows up on the line instead of being silent.
func (l *Logger) Handler() slog.Handler { return l.ops.Handler() }

// Log records an ordinary event.
func (l *Logger) Log(ctx context.Context, ev Event, fs ...Field) {
	l.emit(ctx, l.ops, ev, fs)
}

// Security records an event on the authpriv facility.
func (l *Logger) Security(ctx context.Context, ev Event, fs ...Field) {
	l.emit(ctx, l.sec, ev, fs)
}

// buildAttrs assembles one line's attributes: the event, then extra (attributes only this
// package can build, which is how audit records reach the handler), then the fields.
// Shared by emit and Audit, so the two paths that write a line never drift apart on what
// goes on it.
func buildAttrs(ev Event, extra []slog.Attr, fs []Field) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(fs)+len(extra)+1)
	attrs = append(attrs, slog.Any("event", eventValue{name: ev.name}))
	attrs = append(attrs, extra...)
	for _, f := range fs {
		if a := f.attr(); a.Key != "" {
			attrs = append(attrs, a)
		}
	}
	return attrs
}

// emit is the one path to an ordinary line, level-gated by LogAttrs. Audit does not go
// through here — it calls buildAttrs directly, since it needs the extra audit attribute
// buildAttrs takes and Log/Security never do.
func (l *Logger) emit(ctx context.Context, to *slog.Logger, ev Event, fs []Field) {
	to.LogAttrs(ctx, ev.level, ev.message, buildAttrs(ev, nil, fs)...)
}

type requestIDKey struct{}

// WithRequestID puts a request identifier on the context. The logger emits it on every
// line drawn from that context.
//
// Whether an inbound X-Request-Id header may be trusted is the product's HTTP layer to
// decide, because that is where the proxy configuration lives.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

func requestIDFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDKey{}).(string)
	return id, ok && id != ""
}

// handler filters a record down to what may appear on a line, then hands it to a
// JSONHandler. It is the whole engine: the typed API is a thin layer over it, and a
// product installing it with slog.SetDefault gets the same rules at runtime.
type handler struct {
	inner    slog.Handler
	app      string
	facility int64

	// attrDropped and attrTruncated carry counts from attributes refused or cut at
	// WithAttrs time (a derived logger's .With(...) call), so a line built from a
	// derived handler still reports what it lost instead of going silent about it.
	attrDropped   int
	attrTruncated int
}

// renameSlogKeys puts slog's built-in keys under the suite's names, so a collector sees
// timestamp and message rather than time and msg.
func renameSlogKeys(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		a.Key = "timestamp"
	case slog.MessageKey:
		a.Key = "message"
	}
	return a
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

// WithGroup returns the handler unchanged. Groups would nest keys, and the line has to
// stay flat for cmd/kyauditverify to unmarshal it into an auditchain.Record.
func (h *handler) WithGroup(string) slog.Handler { return h }

// WithAttrs filters the attributes at the point they are attached, so an undeclared key
// cannot be smuggled in on a derived logger. What it refuses is carried forward on the
// derived handler rather than discarded, so a line built from it still counts the loss.
func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	kept, dropped, truncated := h.filter(attrs)
	return &handler{
		inner:         h.inner.WithAttrs(kept),
		app:           h.app,
		facility:      h.facility,
		attrDropped:   h.attrDropped + dropped,
		attrTruncated: h.attrTruncated + truncated,
	}
}

// filter splits attributes into those that may appear and counts of what was refused.
func (h *handler) filter(attrs []slog.Attr) (kept []slog.Attr, dropped, truncated int) {
	for _, a := range attrs {
		switch v := a.Value.Any().(type) {
		case eventValue:
			// Only this package can construct one, so the event key has one source.
			kept = append(kept, slog.String("event", v.name))
		case auditValue:
			kept = append(kept, v.attrs()...)
		case fieldValue:
			if v.truncated {
				truncated++
			}
			kept = append(kept, slog.Attr{Key: a.Key, Value: v.v})
		default:
			// A raw slog attribute. Reserved keys are set by this handler and a
			// second copy would contradict them; undeclared keys are the leak this
			// package exists to prevent.
			if isReserved(a.Key) || !isDeclared(a.Key) {
				dropped++
				continue
			}
			switch a.Value.Kind() {
			case slog.KindString:
				s, cut := sanitize(a.Value.String())
				if cut {
					truncated++
				}
				kept = append(kept, slog.String(a.Key, s))
			case slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindBool,
				slog.KindDuration, slog.KindTime:
				// Bounded, self-describing scalars: emit with their own type intact
				// so a declared int key reads as a JSON number regardless of
				// whether it arrived through the typed API or a raw slog call.
				kept = append(kept, a)
			default:
				// KindAny, KindGroup and KindLogValuer are refused even for a
				// declared key. A declared name only vouches for the key; it says
				// nothing about what a caller stuffed into an arbitrary Go value
				// (or what a LogValuer might resolve to), and this package's rule
				// is that values are typed and bounded — none of these are, and
				// stringifying one would print it onto the line whole.
				dropped++
			}
		}
	}
	return kept, dropped, truncated
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	var attrs []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	kept, dropped, truncated := h.filter(attrs)
	dropped += h.attrDropped
	truncated += h.attrTruncated

	// The message is caller data on every raw slog call site Handler() exists to
	// support, so it gets the same treatment as any string value: no control
	// characters, capped length.
	msg, msgCut := sanitize(r.Message)
	if msgCut {
		truncated++
	}

	out := slog.NewRecord(r.Time, r.Level, msg, r.PC)
	out.AddAttrs(slog.String("app", h.app))
	if id, ok := requestIDFrom(ctx); ok {
		clean, idCut := sanitize(id)
		if idCut {
			truncated++
		}
		out.AddAttrs(slog.String("request_id", clean))
	}
	out.AddAttrs(kept...)
	out.AddAttrs(
		slog.Int64("severity", severityOf(r.Level)),
		slog.Int64("facility", h.facility),
	)
	if dropped > 0 {
		out.AddAttrs(slog.Int("dropped_fields", dropped))
	}
	if truncated > 0 {
		out.AddAttrs(slog.Int("truncated_fields", truncated))
	}
	return h.inner.Handle(ctx, out)
}
