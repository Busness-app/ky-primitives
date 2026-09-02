package password_test

import (
	"errors"
	"testing"

	"github.com/Busness-app/ky-primitives/password"
)

func TestDummyVerifyDoesNotPanic(t *testing.T) {
	password.DummyVerify()
}

func TestNeedsRehashIsFalseForAForeignFormat(t *testing.T) {
	cases := []string{
		"scrypt$131072$8$1$c2FsdA$aGFzaA",
		"$2b$12$abcdefghijklmnopqrstuv",
		"239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
		"",
	}
	for _, encoded := range cases {
		stale, err := password.NeedsRehash(encoded)
		if err != nil {
			t.Errorf("NeedsRehash(%q) = error %v, want (false, nil)", encoded, err)
		}
		if stale {
			t.Errorf("NeedsRehash(%q) = true, want false", encoded)
		}
	}
}

func TestNeedsRehashStillFlagsAWeakOwnHash(t *testing.T) {
	weak, err := password.HashWith("hunter2", password.Params{Memory: 8 * 1024, Time: 1, Threads: 1})
	if err != nil {
		t.Fatalf("HashWith: %v", err)
	}
	stale, err := password.NeedsRehash(weak)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if !stale {
		t.Error("NeedsRehash did not flag a hash below the current parameters")
	}
}

func TestNeedsRehashIsFalseForACurrentHash(t *testing.T) {
	current, err := password.Hash("hunter2")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	stale, err := password.NeedsRehash(current)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if stale {
		t.Error("NeedsRehash flagged a hash minted at the current parameters")
	}
}

// Verify must still refuse a malformed stored hash outright. A fallback there is the
// bug this package exists to remove, and relaxing NeedsRehash must not relax Verify.
func TestVerifyStillErrorsOnAForeignFormat(t *testing.T) {
	if _, err := password.Verify("hunter2", "scrypt$131072$8$1$c2FsdA$aGFzaA"); !errors.Is(err, password.ErrMalformed) {
		t.Errorf("Verify on a foreign format gave %v, want ErrMalformed", err)
	}
}
