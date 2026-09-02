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
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Params are the Argon2id cost parameters. Memory is in KiB.
type Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

// Default is RFC 9106's second recommended option. The first asks for 2 GiB, which no
// login endpoint can afford per request.
var Default = Params{Memory: 64 * 1024, Time: 3, Threads: 4}

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

// ponytail: fixed slot count and wait. 4 slots at 64 MiB caps derivation memory at
// 256 MiB; make them configurable if a deployment needs a different ceiling.
const (
	maxConcurrent = 4
	maxWait       = 2 * time.Second
)

var slots = make(chan struct{}, maxConcurrent)

// withSlot bounds concurrent derivations and sheds past the wait rather than queueing.
// kynotes-server bounds the same way but blocks forever, so a burst of logins parks an
// unbounded number of goroutines and overload reports itself as a wrong password.
func withSlot(fn func()) error {
	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
		fn()
		return nil
	case <-timer.C:
		return ErrBusy
	}
}

// Hash derives a PHC-encoded Argon2id hash at the current parameters.
func Hash(plaintext string) (string, error) {
	return hashWith(plaintext, Default)
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
	if err := withSlot(func() {
		key = argon2.IDKey([]byte(plaintext), salt, p.Time, p.Memory, p.Threads, keyBytes)
	}); err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether plaintext produced encoded. A malformed or out-of-bounds stored
// hash is an error, never a silent fall back to the compiled defaults.
func Verify(plaintext, encoded string) (bool, error) {
	p, salt, want, err := parse(encoded)
	if err != nil {
		return false, err
	}
	var got []byte
	if err := withSlot(func() {
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
	return p.Memory < Default.Memory || p.Time < Default.Time || p.Threads != Default.Threads, nil
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

	var v int
	if n, err := fmt.Sscanf(parts[2], "v=%d", &v); n != 1 || err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: unreadable version %q", ErrMalformed, parts[2])
	}
	if v != version {
		return Params{}, nil, nil, fmt.Errorf("%w: version %d, want %d", ErrMalformed, v, version)
	}

	var p Params
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); n != 3 || err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: unreadable parameters %q", ErrMalformed, parts[3])
	}
	if err := p.validate(); err != nil {
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
