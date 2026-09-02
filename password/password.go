// Package password hashes and verifies passwords with Argon2id.
//
// The suite ran three algorithms and five parameter sets: Argon2id at t=1 in
// ky_server_base and gridlock-server, at t=3 in kysignon-server, kyrecovery-server and
// kydns-server (p=2 there, p=4 elsewhere), and scrypt at N=2^17 in kynotes-server and
// kypost-server and N=2^15 in kybookmarks-server. The Argon2 encodings are mutually
// parseable, so a hash minted at t=1 verified in a t=3 product at a third of the intended
// attacker cost and nothing flagged it.
//
// This package is the suite's one answer: RFC 9106's second recommended profile, 64 MiB
// at t=3 p=4, self-describing in PHC form.
//
// It is the only package in this module with a dependency. Argon2 is not in the standard
// library and is not on a proposal track, so the module's rule bends exactly once, here,
// and TestModuleDependenciesAreAllowlisted holds the line at x/crypto.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Params are the Argon2id cost parameters. Memory is in KiB.
type Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

// DefaultParams returns RFC 9106's second recommended option. The first asks for 2 GiB,
// which no login endpoint can afford per request.
//
// A function rather than a variable: an exported var is global policy any importer can
// assign to, and a configuration reload writing it while a login reads it is a data race
// that also lets two concurrent hashes use different parameters. Callers wanting other
// costs pass a Params to a call, they do not edit everyone else's.
func DefaultParams() Params {
	return Params{Memory: defaultMemory, Time: defaultTime, Threads: defaultThreads}
}

const (
	defaultMemory  = 64 * 1024
	defaultTime    = 3
	defaultThreads = 4
)

const (
	saltBytes = 16
	keyBytes  = 32
	version   = argon2.Version // 19

	// Bounds on what a stored hash may ask for. A stored hash is attacker-controlled
	// wherever the store is, and one asking for terabytes OOM-kills the process on the
	// next login rather than failing that login.
	minMemory  = 8 * 1024
	maxMemory  = 256 * 1024
	minTime    = 1
	maxTime    = 10
	minThreads = 1
	maxThreads = 16
	minSalt    = 8
	minKey     = 16
	maxDecoded = 1024
)

var (
	// ErrBusy reports that too many derivations are already running. Callers should
	// answer 503 and must not spend a lockout strike: this is the server saying "not
	// now", not the user getting the password wrong.
	ErrBusy = errors.New("password: too many concurrent derivations")
	// ErrMalformed reports a stored hash that is not a well-formed Argon2id PHC string.
	// It is never treated as a verification failure against default parameters.
	ErrMalformed = errors.New("password: stored hash is not a valid argon2id PHC string")
)

// ponytail: fixed budget and wait. Make them configurable if a deployment needs a
// different ceiling.
const (
	// budgetKiB is the total memory all concurrent derivations may reserve, equal to
	// four derivations at the default 64 MiB.
	//
	// It is a byte budget rather than a slot count because slots bound how many
	// derivations run, not how large they are, and Verify accepts a stored hash asking
	// for anything up to maxMemory. Four slots therefore admitted 4 x 256 MiB while this
	// comment claimed 256 MiB. Reserving p.Memory makes the number here the number
	// enforced.
	budgetKiB = 4 * 64 * 1024
	maxWait   = 2 * time.Second
)

// Memory is what OOM-kills a process, so it is what the budget counts. Time and Threads
// cost CPU, which degrades rather than kills, and the wait below sheds that.
var budget = struct {
	admit chan struct{} // capacity 1: one acquirer negotiates at a time
	wake  chan struct{} // poked on release
	mu    sync.Mutex
	free  int64
	peak  int64
}{
	admit: make(chan struct{}, 1),
	wake:  make(chan struct{}, 1),
	free:  budgetKiB,
}

// withMemory runs fn holding a reservation of kib, or reports ErrBusy.
//
// Reservations are serialised through admit so that no two acquirers can each hold part of
// what the other needs, which is the deadlock a naive multi-token semaphore has. It also
// makes the queue first-come rather than letting small requests starve a large one. Only
// the reservation is serialised; the derivation itself runs outside the queue.
func withMemory(kib int64, fn func()) error {
	if kib > budgetKiB {
		// Unsatisfiable however long we wait, so say so now rather than after maxWait.
		return fmt.Errorf("%w: needs %d KiB, the whole budget is %d KiB", ErrBusy, kib, budgetKiB)
	}
	timer := time.NewTimer(maxWait)
	defer timer.Stop()

	select {
	case budget.admit <- struct{}{}:
	case <-timer.C:
		return ErrBusy
	}
	admitted := true
	leaveQueue := func() {
		if admitted {
			admitted = false
			<-budget.admit
		}
	}
	defer leaveQueue()

	for {
		budget.mu.Lock()
		if budget.free >= kib {
			budget.free -= kib
			if used := budgetKiB - budget.free; used > budget.peak {
				budget.peak = used
			}
			budget.mu.Unlock()
			// Admit is the queue, not the reservation. Deriving while holding it capped
			// the package at one derivation at a time whatever the budget allowed, and
			// left the wait below unreachable.
			leaveQueue()
			defer releaseMemory(kib)
			fn()
			return nil
		}
		budget.mu.Unlock()

		select {
		case <-budget.wake:
		case <-timer.C:
			return ErrBusy
		}
	}
}

// releaseMemory returns a reservation and wakes whoever is queued behind it.
func releaseMemory(kib int64) {
	budget.mu.Lock()
	budget.free += kib
	budget.mu.Unlock()
	select {
	case budget.wake <- struct{}{}:
	default:
	}
}

// peakReserved, inFlight and resetPeak exist for the budget test, which cannot observe a
// ceiling it has no way to measure.
func peakReserved() int64 {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.peak
}

func inFlight() int64 {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budgetKiB - budget.free
}

func resetPeak() {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	budget.peak = 0
}

// Hash derives a PHC-encoded Argon2id hash at the current parameters.
func Hash(plaintext string) (string, error) {
	return hashWith(plaintext, DefaultParams())
}

func hashWith(plaintext string, p Params) (string, error) {
	if plaintext == "" {
		return "", errors.New("password: refusing to hash an empty password")
	}
	if err := p.validate(); err != nil {
		return "", err
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: %w", err)
	}
	var key []byte
	if err := withMemory(int64(p.Memory), func() {
		key = argon2.IDKey([]byte(plaintext), salt, p.Time, p.Memory, p.Threads, keyBytes)
	}); err != nil {
		return "", err
	}
	return "$argon2id$" + versionSegment + "$" + p.segment() + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(key), nil
}

// Verify reports whether plaintext produced encoded. A malformed or out-of-bounds stored
// hash is an error, never a silent fall back to the compiled defaults.
func Verify(plaintext, encoded string) (bool, error) {
	p, salt, want, err := parse(encoded)
	if err != nil {
		return false, err
	}
	var got []byte
	if err := withMemory(int64(p.Memory), func() {
		got = argon2.IDKey([]byte(plaintext), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	}); err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash reports whether a stored hash was made below the current parameters, so a
// deployment can upgrade it on the next successful login.
func NeedsRehash(encoded string) (bool, error) {
	p, _, _, err := parse(encoded)
	if err != nil {
		return false, err
	}
	d := DefaultParams()
	return p.Memory < d.Memory || p.Time < d.Time || p.Threads != d.Threads, nil
}

// versionSegment is the only version segment this package accepts or emits.
var versionSegment = "v=" + strconv.Itoa(version)

// parseParams reads "m=<n>,t=<n>,p=<n>" and nothing else.
//
// Every field is parsed with strconv, then the whole segment is re-encoded and compared
// to the input. That one comparison is what rejects trailing garbage, a fourth field,
// reordering, leading zeros, a leading plus and surrounding space, without a rule for
// each: a stored hash either spells its parameters the way this package spells them or it
// is not a hash this package wrote.
func parseParams(segment string) (Params, error) {
	fields := strings.Split(segment, ",")
	if len(fields) != 3 {
		return Params{}, fmt.Errorf("%w: parameter segment %q has %d fields, want 3", ErrMalformed, segment, len(fields))
	}
	var values [3]uint64
	for i, prefix := range [3]string{"m=", "t=", "p="} {
		if !strings.HasPrefix(fields[i], prefix) {
			return Params{}, fmt.Errorf("%w: parameter %d is %q, want a %q field", ErrMalformed, i, fields[i], prefix)
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(fields[i], prefix), 10, 32)
		if err != nil {
			return Params{}, fmt.Errorf("%w: parameter %q: %v", ErrMalformed, fields[i], err)
		}
		values[i] = v
	}
	if values[2] > 255 {
		return Params{}, fmt.Errorf("%w: threads %d does not fit a uint8", ErrMalformed, values[2])
	}
	p := Params{Memory: uint32(values[0]), Time: uint32(values[1]), Threads: uint8(values[2])}
	if canonical := p.segment(); canonical != segment {
		return Params{}, fmt.Errorf("%w: parameter segment %q is not canonical, want %q", ErrMalformed, segment, canonical)
	}
	return p, p.validate()
}

// segment renders the canonical parameter spelling.
func (p Params) segment() string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", p.Memory, p.Time, p.Threads)
}

func (p Params) validate() error {
	switch {
	case p.Memory < minMemory || p.Memory > maxMemory:
		return fmt.Errorf("%w: memory %d KiB is outside %d-%d", ErrMalformed, p.Memory, minMemory, maxMemory)
	case p.Time < minTime || p.Time > maxTime:
		return fmt.Errorf("%w: time %d is outside %d-%d", ErrMalformed, p.Time, minTime, maxTime)
	case p.Threads < minThreads || p.Threads > maxThreads:
		return fmt.Errorf("%w: threads %d is outside %d-%d", ErrMalformed, p.Threads, minThreads, maxThreads)
	}
	return nil
}

// parse reads a PHC string strictly: every segment must be present and well formed.
func parse(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return Params{}, nil, nil, fmt.Errorf("%w: %d segments", ErrMalformed, len(parts))
	}
	if parts[1] != "argon2id" {
		return Params{}, nil, nil, fmt.Errorf("%w: algorithm %q", ErrMalformed, parts[1])
	}

	// Exact string comparison rather than a scan: fmt.Sscanf reads the fields it is
	// asked for and ignores whatever follows, so "v=19GARBAGE" and "m=...,p=04" both
	// parsed clean. A stored hash has exactly one canonical spelling.
	if parts[2] != versionSegment {
		return Params{}, nil, nil, fmt.Errorf("%w: version segment %q, want %q", ErrMalformed, parts[2], versionSegment)
	}

	p, err := parseParams(parts[3])
	if err != nil {
		return Params{}, nil, nil, err
	}

	salt, err := decode(parts[4], minSalt)
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: salt: %v", ErrMalformed, err)
	}
	key, err := decode(parts[5], minKey)
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: hash: %v", ErrMalformed, err)
	}
	return p, salt, key, nil
}

func decode(s string, min int) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) < min || len(b) > maxDecoded {
		return nil, fmt.Errorf("%d bytes, want %d-%d", len(b), min, maxDecoded)
	}
	return b, nil
}
