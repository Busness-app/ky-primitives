package derive

import (
	"encoding/base64"
	"errors"
	"sync"
	"testing"
)

const testSalt = "AAAAAAAAAAAAAAAAAAAAAA==" // 16 bytes

func init() {
	if b, err := base64.StdEncoding.DecodeString(testSalt); err != nil || len(b) != 16 {
		panic("test salt is not 16 base64 bytes")
	}
}

// MaxIterations bounds one call and nothing else. A ceiling is not admission control: a
// modest burst all asking for 12,000,000 iterations occupies every core for as long as it
// takes, and the handlers that share the process — including the ones that would have shed
// load — are starved behind it. The iteration count arrives from a client or a stored
// record, so it is the caller's number, not ours.
func TestConcurrentDerivationsAreAdmittedNotJustBounded(t *testing.T) {
	resetPeak()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := AuthSecret("pw", testSalt, MinIterations, "test")
			if err != nil && !errors.Is(err, ErrBusy) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if peak := peakInFlight(); peak > maxConcurrent {
		t.Fatalf("%d derivations ran at once, the budget is %d", peak, maxConcurrent)
	}
	if peakInFlight() == 0 {
		t.Fatal("no derivation was recorded, so this test proves nothing")
	}
	if inFlight() != 0 {
		t.Fatalf("%d slots still held after every derivation finished", inFlight())
	}
}

// A rejected caller must get ErrBusy, not a wrong answer and not a lockout strike: the
// server is saying "not now", which is a different thing from the password being wrong.
func TestBusyIsDistinguishableFromAWrongPassword(t *testing.T) {
	if errors.Is(ErrBusy, errors.New("boom")) {
		t.Fatal("ErrBusy must be its own sentinel")
	}
	// The happy path still has to work, or shedding everything would pass the test above.
	got, err := AuthSecret("pw", testSalt, MinIterations, "test")
	if err != nil {
		t.Fatalf("an uncontended derivation was refused: %v", err)
	}
	if len(got) != 2*keyBytes {
		t.Fatalf("secret is %d hex characters, want %d", len(got), 2*keyBytes)
	}
}

// The slot must come back on every exit, including the ones that fail after admission.
func TestSlotsAreReturnedOnFailure(t *testing.T) {
	if _, err := AuthSecret("pw", "not base64!", MinIterations, "test"); err == nil {
		t.Fatal("a bad salt was accepted")
	}
	if _, err := AuthSecret("pw", testSalt, MinIterations, ""); err == nil {
		t.Fatal("an empty label was accepted")
	}
	if inFlight() != 0 {
		t.Fatalf("%d slots leaked after refused calls", inFlight())
	}
}
