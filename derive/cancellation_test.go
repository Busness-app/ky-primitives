package derive

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// TestAuthSecretContextRefusesACancelledContextBeforeQueueing pins the property this task
// exists for: a caller whose context is already done must be refused before it takes a
// slot, not after losing a race for one.
//
// It holds every slot but one. With none held, a select racing slots<-struct{}{} against
// ctx.Done() has both arms ready and Go picks one at random — deleting the ctx.Err()
// pre-check still refuses correctly about half the time, which a single run cannot catch
// (confirmed separately: with the pre-check removed, the earlier one-shot version of this
// test passed 20/20 when every slot was held, because a full channel makes the send arm
// unready regardless of the pre-check and so proves nothing about it; holding all-but-one
// keeps the race genuine). Repeating the call drives the chance of never observing the bug
// down to roughly 0.5^300, which is what makes this deterministic in practice.
func TestAuthSecretContextRefusesACancelledContextBeforeQueueing(t *testing.T) {
	resetPeak()

	acquired := 0
	defer func() {
		for ; acquired > 0; acquired-- {
			release()
		}
	}()
	for i := 0; i < MaxConcurrent-1; i++ {
		if err := acquire(context.Background()); err != nil {
			t.Fatalf("acquire %d/%d: %v", i+1, MaxConcurrent-1, err)
		}
		acquired++
	}
	baselinePeak := peakInFlight()

	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	const attempts = 300
	start := time.Now()
	for i := 0; i < attempts; i++ {
		_, err := AuthSecretContext(ctx, "hunter2", salt, MinIterations, "test")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("attempt %d/%d: cancelled context gave %v, want context.Canceled — it took the free slot instead of refusing up front", i+1, attempts, err)
		}
	}
	elapsed := time.Since(start)

	// A pre-check refuses every attempt in microseconds. A post-queue refusal would have
	// waited out the full maxWait (2s) at least once across this many attempts.
	if elapsed >= maxWait {
		t.Errorf("%d cancelled calls took %v, want well under maxWait (%v)", attempts, elapsed, maxWait)
	}
	if peakInFlight() != baselinePeak {
		t.Errorf("peakInFlight moved from %d to %d; a cancelled call touched the meter, so it took the free slot", baselinePeak, peakInFlight())
	}
}
