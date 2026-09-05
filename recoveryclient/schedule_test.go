package recoveryclient

import (
	"errors"
	"testing"
	"time"
)

func TestSetIntervalBoundsSeconds(t *testing.T) {
	s := memSettings{}
	for _, bad := range []int64{1, 899, -3600, 36028797018963968, int64(MaxInterval/time.Second) + 1} {
		if err := SetInterval(s, bad); !errors.Is(err, ErrBadInterval) {
			t.Errorf("%d: %v", bad, err)
		}
	}
	for _, ok := range []int64{0, 900, 3600, int64(MaxInterval / time.Second)} {
		if err := SetInterval(s, ok); err != nil {
			t.Errorf("%d: %v", ok, err)
		}
	}
}

func TestIntervalFallsBackToDefault(t *testing.T) {
	s := memSettings{}
	if d, err := Interval(24*time.Hour, s); err != nil || d != 24*time.Hour {
		t.Fatalf("%v %v", d, err)
	}
	_ = SetInterval(s, 3600)
	if d, _ := Interval(24*time.Hour, s); d != time.Hour {
		t.Fatalf("%v", d)
	}
}

func TestNextRunCountsFromLastAttempt(t *testing.T) {
	s := memSettings{}
	if _, on, _ := NextRun(0, s); on {
		t.Fatal("off schedule reported on")
	}
	_ = SetInterval(s, 3600)
	next, on, err := NextRun(0, s)
	if err != nil || !on || next.After(time.Now()) {
		t.Fatalf("never attempted: %v %v %v", next, on, err)
	}
	if err := markAttempt(s); err != nil {
		t.Fatal(err)
	}
	next, on, _ = NextRun(0, s)
	if !on || next.Before(time.Now().Add(59*time.Minute)) {
		t.Fatalf("after attempt: %v", next)
	}
}
