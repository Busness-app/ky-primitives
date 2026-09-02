package auditchain

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// buildChain returns a chain of n records and the anchor over all of them.
func buildChain(t *testing.T, n int) ([]Record, Anchor) {
	t.Helper()
	c, err := New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	var recs []Record
	var anchor Anchor
	for i := 0; i < n; i++ {
		rec, err := c.Append(context.Background(), func(r Record, a Anchor) error {
			recs = append(recs, r)
			anchor = a
			return nil
		}, "event")
		if err != nil {
			t.Fatal(err)
		}
		_ = rec
	}
	return recs, anchor
}

// Resume proved one thing: that the record it was handed carries its own digest. That is
// not the same as it being the tail. Every record in a healthy chain carries its own
// digest, so resuming from the middle of one was accepted, and the next append minted a
// sequence number that already existed — a fork, persisted successfully, that Verify then
// rejects forever. The anchor is the only thing that knows where the end is, so Resume
// has to be shown it.
func TestResumeRefusesARecordThatIsNotTheTail(t *testing.T) {
	recs, tail := buildChain(t, 5)

	if _, err := Resume(testKey(), recs[2], tail); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("got %v, want ErrBrokenChain resuming from record 3 of 5", err)
	}
}

// The matching pair is the whole point, so it must still work.
func TestResumeAcceptsTheTailWithItsAnchor(t *testing.T) {
	recs, tail := buildChain(t, 5)

	c, err := Resume(testKey(), recs[len(recs)-1], tail)
	if err != nil {
		t.Fatalf("the real tail and its own anchor were refused: %v", err)
	}
	rec, err := c.Append(context.Background(), func(Record, Anchor) error { return nil }, "next")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Seq != 6 {
		t.Fatalf("resumed chain minted sequence %d, want 6", rec.Seq)
	}
}

// An anchor that agrees about the hash but not the count, or the reverse, is a store that
// disagrees with itself.
func TestResumeRefusesAMismatchedAnchor(t *testing.T) {
	recs, tail := buildChain(t, 3)
	last := recs[len(recs)-1]

	for name, a := range map[string]Anchor{
		"count disagrees": {Count: tail.Count + 1, Hash: tail.Hash},
		"hash disagrees":  {Count: tail.Count, Hash: genesis},
		"empty anchor":    {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Resume(testKey(), last, a); !errors.Is(err, ErrBrokenChain) {
				t.Fatalf("got %v, want ErrBrokenChain", err)
			}
		})
	}
}

// Append mints c.count+1. A correctly signed record at the top of the range therefore
// wraps the next one to zero, which persists cleanly and can never be verified again.
// Sequence zero is the mirror image: no record legitimately carries it, because Append
// starts at one.
func TestResumeRefusesUnusableSequenceNumbers(t *testing.T) {
	key := testKey()
	for name, seq := range map[string]uint64{
		"zero":     0,
		"overflow": math.MaxUint64,
	} {
		t.Run(name, func(t *testing.T) {
			rec := Record{Seq: seq, Prev: genesis, Fields: []string{"a"}}
			rec.Hash = digest(key, rec.Seq, rec.Prev, rec.Fields)

			if _, err := Resume(key, rec, Anchor{Count: seq, Hash: rec.Hash}); !errors.Is(err, ErrBrokenChain) {
				t.Fatalf("got %v, want ErrBrokenChain for sequence %d", err, seq)
			}
		})
	}
}

// persist runs under the lock that reserves the sequence number, which is deliberate: the
// record and its anchor have to be written together. The cost is that a hung store owns
// the chain, and every later append — and every Anchor() call — waited on it with no way
// out. A waiter can now give up.
func TestAppendWaiterGivesUpWhenTheStoreHangs(t *testing.T) {
	c, err := New(testKey())
	if err != nil {
		t.Fatal(err)
	}

	hung := make(chan struct{})
	entered := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.Append(context.Background(), func(Record, Anchor) error {
			close(entered)
			<-hung
			return nil
		}, "first")
	}()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = c.Append(ctx, func(Record, Anchor) error { return nil }, "second")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded while the store is hung", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waiter took %v to give up", elapsed)
	}

	close(hung)
	<-done
}

// Giving up must not consume the sequence number, or a shed append leaves a hole the
// verifier reports as a broken chain.
func TestAGivenUpAppendLeavesTheChainWhereItWas(t *testing.T) {
	c, err := New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(context.Background(), func(Record, Anchor) error { return nil }, "first"); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Append(ctx, func(Record, Anchor) error { return nil }, "shed"); err == nil {
		t.Fatal("a cancelled append was accepted")
	}

	rec, err := c.Append(context.Background(), func(Record, Anchor) error { return nil }, "second")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Seq != 2 {
		t.Fatalf("next sequence is %d, want 2", rec.Seq)
	}
}
