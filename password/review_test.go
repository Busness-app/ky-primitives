package password

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Finding 4.2: fmt.Sscanf reads the fields it is asked for and ignores whatever follows,
// so a segment that merely starts correctly was accepted. The package documents the
// parser as strict; it was not.
func TestParserRejectsNonCanonicalSegments(t *testing.T) {
	good, err := Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(good, "$")
	tail := "$" + p[4] + "$" + p[5]

	for _, seg := range []string{
		"m=65536,t=3,p=4TRAILINGGARBAGE",
		"m=65536,t=3,p=4,junk=1",
		"m=65536,t=3,p=04",
		"m=065536,t=3,p=4",
		"m=+65536,t=3,p=4",
		"m=65536,t=3",
		"m=65536,p=4,t=3",
		"t=3,m=65536,p=4",
		"m=65536,t=3,p= 4",
		" m=65536,t=3,p=4",
		"m=65536,t=3,p=4 ",
		"m=0x10000,t=3,p=4",
		"m=65536,t=3,p=4,",
	} {
		t.Run(seg, func(t *testing.T) {
			if ok, err := Verify("pw", "$argon2id$v=19$"+seg+tail); ok || err == nil {
				t.Fatalf("accepted: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestParserRejectsNonCanonicalVersion(t *testing.T) {
	good, err := Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(good, "$")
	tail := "$" + p[4] + "$" + p[5]

	for _, v := range []string{"v=19GARBAGE", "v=019", "v=+19", "v=19 ", "V=19", "v=", "19"} {
		t.Run(v, func(t *testing.T) {
			if ok, err := Verify("pw", "$argon2id$"+v+"$m=65536,t=3,p=4"+tail); ok || err == nil {
				t.Fatalf("accepted: ok=%v err=%v", ok, err)
			}
		})
	}
}

// The canonical form this package writes must still verify, or the strictness has eaten
// its own output.
func TestCanonicalFormStillVerifies(t *testing.T) {
	for _, params := range []Params{DefaultParams(), {Memory: 16384, Time: 1, Threads: 4}, {Memory: 8192, Time: 10, Threads: 16}} {
		encoded, err := hashWith("pw", params)
		if err != nil {
			t.Fatalf("%+v: %v", params, err)
		}
		ok, err := Verify("pw", encoded)
		if err != nil || !ok {
			t.Fatalf("%+v: ok=%v err=%v", params, ok, err)
		}
	}
}

// Finding 1.2: the slot count bounded the number of derivations, not their size.
// Verification accepts a stored hash up to maxMemory, so four concurrent verifications
// of attacker-supplied hashes could reserve 4 x 256 MiB while the code claimed a 256 MiB
// ceiling. The budget is in bytes now, so the claim is the thing enforced.
func TestConcurrentDerivationsRespectTheMemoryBudget(t *testing.T) {
	heavy, err := hashWith("pw", Params{Memory: maxMemory, Time: 1, Threads: 4})
	if err != nil {
		t.Fatal(err)
	}
	light, err := hashWith("pw", Params{Memory: minMemory, Time: 1, Threads: 4})
	if err != nil {
		t.Fatal(err)
	}

	resetPeak()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		encoded := light
		if i%3 == 0 {
			encoded = heavy
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := Verify("pw", encoded)
			if err != nil && !errors.Is(err, ErrBusy) {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && !ok {
				t.Error("a correct password failed to verify")
			}
		}()
	}
	wg.Wait()

	if peak := peakReserved(); peak > budgetKiB {
		t.Fatalf("peak reservation was %d KiB, over the %d KiB budget", peak, budgetKiB)
	}
	if peakReserved() == 0 {
		t.Fatal("no reservation was recorded, so this test proves nothing")
	}
	if inFlight() != 0 {
		t.Fatalf("%d KiB still reserved after every derivation finished", inFlight())
	}
}

// A hash needing more than the entire budget can never be admitted, so it must fail fast
// rather than block for the full wait and then report a timeout.
func TestAHashLargerThanTheWholeBudgetIsRejectedImmediately(t *testing.T) {
	start := time.Now()
	_, err := Verify("pw", "$argon2id$v=19$m=99999999,t=3,p=4$"+strings.Repeat("A", 22)+"$"+strings.Repeat("A", 43))
	if err == nil {
		t.Fatal("accepted a hash asking for more memory than the budget")
	}
	if elapsed := time.Since(start); elapsed > maxWait {
		t.Fatalf("took %v, which means it waited for a slot it could never get", elapsed)
	}
}

// The budget holds admit only to negotiate a reservation. Holding it across the derivation
// capped the package at one derivation at a time however much budget was free, and made
// the wait-and-retry loop unreachable — a ceiling the peak test cannot see, because a peak
// under the budget is trivially true when only one derivation ever runs.
func TestDerivationsRunConcurrentlyWithinTheBudget(t *testing.T) {
	const n = 4
	arrived := make(chan struct{}, n)
	release := make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()

	errs := make(chan error, n)
	for range n {
		go func() {
			errs <- withBudget(budgetKiB/n, 1, func() {
				arrived <- struct{}{}
				<-release
			})
		}()
	}

	for i := range n {
		select {
		case <-arrived:
		case <-time.After(maxWait + 5*time.Second):
			t.Fatalf("only %d of %d derivations were admitted; the budget serialises them", i, n)
		}
	}
	stop()

	for range n {
		if err := <-errs; err != nil {
			t.Fatalf("a derivation inside the budget was refused: %v", err)
		}
	}
	if inFlight() != 0 {
		t.Fatalf("%d KiB still reserved after every derivation finished", inFlight())
	}
}
