package logging

import (
	"log/slog"
	"sync"
)

// Event is what happened. It carries its name, its message and its level, so all three
// agree across the suite and none of them is supplied at the call site.
//
// There is deliberately no free-text message parameter anywhere in this package. One
// would be the last remaining channel for an accidental leak — Log(ctx, AuthFailed,
// fmt.Sprintf("user %s failed", email)) defeats every other rule here — and a constant
// message also means the same event reads the same way in every product.
type Event struct {
	name    string
	message string
	level   slog.Level
}

// eventValue carries an event name to the handler. Its type is unexported, so code
// outside this package cannot construct one and cannot set the event key.
type eventValue struct{ name string }

var (
	eventsMu sync.Mutex
	events   = map[string]bool{}
)

// DeclareEvent admits an event and returns it. Call it once, at package level.
func DeclareEvent(name, message string, lvl slog.Level) Event {
	if !keyPattern.MatchString(name) {
		panic("logging: event name " + name + " must match [a-z][a-z0-9_]*")
	}
	if message == "" {
		panic("logging: event " + name + " needs a message; the call site cannot supply one")
	}
	eventsMu.Lock()
	defer eventsMu.Unlock()
	if events[name] {
		panic("logging: event " + name + " is already declared")
	}
	events[name] = true
	return Event{name: name, message: message, level: lvl}
}

// severityOf maps a slog level to an RFC 5424 severity, so a collector can route on a
// number without carrying a mapping table for us. Derived from RFC 5424 section 6.2.1.
func severityOf(l slog.Level) int64 {
	switch {
	case l >= slog.LevelError:
		return 3 // error
	case l >= slog.LevelWarn:
		return 4 // warning
	case l >= slog.LevelInfo:
		return 6 // informational
	default:
		return 7 // debug
	}
}

// The starter set, drawn from what the nine products log today. A product adds its own
// with DeclareEvent.
var (
	Started      = DeclareEvent("started", "service started", slog.LevelInfo)
	Stopped      = DeclareEvent("stopped", "service stopped", slog.LevelInfo)
	ConfigLoaded = DeclareEvent("config_loaded", "configuration loaded", slog.LevelInfo)

	AuthSucceeded  = DeclareEvent("auth_succeeded", "authentication succeeded", slog.LevelInfo)
	AuthFailed     = DeclareEvent("auth_failed", "authentication failed", slog.LevelWarn)
	AuthLocked     = DeclareEvent("auth_locked", "account locked after repeated failures", slog.LevelWarn)
	SessionCreated = DeclareEvent("session_created", "session created", slog.LevelInfo)
	SessionRevoked = DeclareEvent("session_revoked", "session revoked", slog.LevelInfo)
	MFAChallenged  = DeclareEvent("mfa_challenged", "second factor requested", slog.LevelInfo)
	MFAFailed      = DeclareEvent("mfa_failed", "second factor rejected", slog.LevelWarn)
	RateLimited    = DeclareEvent("rate_limited", "request rate limited", slog.LevelWarn)
	AdminAction    = DeclareEvent("admin_action", "administrative action performed", slog.LevelWarn)

	KeyCreated = DeclareEvent("key_created", "key created", slog.LevelInfo)
	KeyRotated = DeclareEvent("key_rotated", "key rotated", slog.LevelInfo)

	CapsuleSealed        = DeclareEvent("capsule_sealed", "capsule sealed", slog.LevelInfo)
	CapsuleOpened        = DeclareEvent("capsule_opened", "capsule opened", slog.LevelInfo)
	CapsuleOpenFailed    = DeclareEvent("capsule_open_failed", "capsule failed to open", slog.LevelWarn)
	ShareIssued          = DeclareEvent("share_issued", "recovery share issued", slog.LevelInfo)
	ShareRedeemed        = DeclareEvent("share_redeemed", "recovery share redeemed", slog.LevelWarn)
	RecoveryCodeRedeemed = DeclareEvent("recovery_code_redeemed", "recovery code redeemed", slog.LevelWarn)
	AuditChainBroken     = DeclareEvent("audit_chain_broken", "audit chain failed verification", slog.LevelError)
)
