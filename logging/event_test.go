package logging

import (
	"log/slog"
	"testing"
)

func TestSeverityMapsToRFC5424(t *testing.T) {
	// Hand-derived from RFC 5424 section 6.2.1: 3 error, 4 warning,
	// 6 informational, 7 debug.
	for _, tc := range []struct {
		level slog.Level
		want  int64
	}{
		{slog.LevelDebug, 7},
		{slog.LevelInfo, 6},
		{slog.LevelWarn, 4},
		{slog.LevelError, 3},
		{slog.LevelError + 4, 3},
		{slog.LevelDebug - 4, 7},
	} {
		if got := severityOf(tc.level); got != tc.want {
			t.Errorf("severityOf(%v) = %d, want %d", tc.level, got, tc.want)
		}
	}
}

func TestDeclareEventRefusesBadNames(t *testing.T) {
	for _, tc := range []struct{ name, key string }{
		{"uppercase", "AuthFailed"},
		{"hyphen", "auth-failed"},
		{"empty", ""},
		{"already declared", "auth_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("DeclareEvent(%q) did not panic", tc.key)
				}
			}()
			DeclareEvent(tc.key, "some message", slog.LevelInfo)
		})
	}
}

func TestDeclareEventRefusesAnEmptyMessage(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("an event with no message did not panic")
		}
	}()
	DeclareEvent("a_fresh_event", "", slog.LevelInfo)
}

func TestSecurityEventsCarryTheRightLevels(t *testing.T) {
	// The point of declaring levels centrally is that a failed login is a
	// warning in all nine products, not info in six of them.
	for _, tc := range []struct {
		ev   Event
		want slog.Level
	}{
		{Started, slog.LevelInfo},
		{AuthSucceeded, slog.LevelInfo},
		{AuthFailed, slog.LevelWarn},
		{AuthLocked, slog.LevelWarn},
		{MFAFailed, slog.LevelWarn},
		{RateLimited, slog.LevelWarn},
		{ShareRedeemed, slog.LevelWarn},
		{AuditChainBroken, slog.LevelError},
	} {
		if tc.ev.level != tc.want {
			t.Errorf("%s is %v, want %v", tc.ev.name, tc.ev.level, tc.want)
		}
	}
}
