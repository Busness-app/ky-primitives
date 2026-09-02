package password

import (
	"errors"
	"sync"
	"testing"
)

// The budget counted memory only, on the reasoning that CPU "degrades rather than kills".
// That holds for one derivation and not for the fleet of them a byte budget admits: a
// stored hash at the minimum 8 MiB reserves a thirty-second of the budget, so 32 of them
// run at once, and each may ask for 16 lanes and 10 iterations. 512 Argon2 lanes on a
// machine with a handful of cores stays comfortably under the advertised memory ceiling
// while taking the login endpoint with it — and the parameters are read out of the stored
// hash, so an attacker who can poison the store picks them.
//
// Lanes are reserved alongside memory, under the same queue, so the number below is the
// number enforced.
func TestConcurrentDerivationsRespectTheLaneBudget(t *testing.T) {
	// Minimum memory, maximum parallelism: the shape that slipped through a byte budget.
	cheap, err := hashWith("pw", Params{Memory: minMemory, Time: minTime, Threads: maxThreads})
	if err != nil {
		t.Fatal(err)
	}

	resetPeak()
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := Verify("pw", cheap)
			if err != nil && !errors.Is(err, ErrBusy) {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && !ok {
				t.Error("a correct password failed to verify")
			}
		}()
	}
	wg.Wait()

	if peak := peakLanes(); peak > budgetLanes {
		t.Fatalf("peak was %d lanes, over the %d lane budget", peak, budgetLanes)
	}
	if peakLanes() == 0 {
		t.Fatal("no lane reservation was recorded, so this test proves nothing")
	}
	if lanesInFlight() != 0 {
		t.Fatalf("%d lanes still reserved after every derivation finished", lanesInFlight())
	}
}

// Memory and lanes are reserved together under one queue. Releasing them together is what
// keeps the second dimension from leaking a little on every busy path until nothing can
// be admitted at all.
func TestBothBudgetsAreReturnedAfterABusyRejection(t *testing.T) {
	unsatisfiable := Params{Memory: maxMemory, Time: minTime, Threads: maxThreads}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = hashWith("pw", unsatisfiable)
		}()
	}
	wg.Wait()

	if inFlight() != 0 {
		t.Errorf("%d KiB still reserved once every derivation finished", inFlight())
	}
	if lanesInFlight() != 0 {
		t.Errorf("%d lanes still reserved once every derivation finished", lanesInFlight())
	}
}
