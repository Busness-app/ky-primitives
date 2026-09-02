// Package derive computes the login secret a client sends in place of a password.
//
// The password is stretched with PBKDF2-SHA256 and the result is expanded through
// HKDF-SHA256 under a per-product label. kynotes-server and kypost-server both do this,
// each mirroring a browser-side TypeScript implementation, which makes it a contract
// across four programs rather than a helper: change any byte and every user is locked out.
// The golden vectors in the test come from kynotes-server's implementation, not this one.
//
// Both existing copies import golang.org/x/crypto/pbkdf2 and .../hkdf. Both moved into
// the standard library in Go 1.24, so adopting this package deletes a dependency from each
// rather than adding one — which is why it can live here at all.
package derive

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ErrBusy reports that too many stretches are already running. Callers should answer 503
// and must not spend a lockout strike: this is the server saying "not now", not the user
// getting the password wrong.
var ErrBusy = errors.New("derive: too many concurrent derivations")

// ponytail: fixed budget and wait. Make them configurable if a deployment needs a
// different ceiling.
const (
	// maxConcurrent bounds how many stretches run at once.
	//
	// MaxIterations bounds one call, which is not admission control: a burst all asking
	// for the ceiling occupies every core for as long as it takes, and everything sharing
	// the process waits behind it. The iteration count comes from a client or a stored
	// record, so the expensive number is the caller's to choose and the concurrency is
	// ours. PBKDF2 is single-threaded, so a slot really is a core.
	maxConcurrent = 4
	maxWait       = 2 * time.Second
)

// slots is the admission queue. A plain buffered channel is the whole mechanism: there is
// one resource here, unlike password, where memory and lanes have to be taken together.
var slots = make(chan struct{}, maxConcurrent)

var meter struct {
	mu   sync.Mutex
	held int64
	peak int64
}

// acquire takes a slot or reports ErrBusy after maxWait.
func acquire() error {
	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	select {
	case slots <- struct{}{}:
		meter.mu.Lock()
		meter.held++
		if meter.held > meter.peak {
			meter.peak = meter.held
		}
		meter.mu.Unlock()
		return nil
	case <-timer.C:
		return ErrBusy
	}
}

func release() {
	meter.mu.Lock()
	meter.held--
	meter.mu.Unlock()
	<-slots
}

// peakInFlight, inFlight and resetPeak exist for the admission test, which cannot observe
// a ceiling it has no way to measure.
func peakInFlight() int64 {
	meter.mu.Lock()
	defer meter.mu.Unlock()
	return meter.peak
}

func inFlight() int64 {
	meter.mu.Lock()
	defer meter.mu.Unlock()
	return meter.held
}

func resetPeak() {
	meter.mu.Lock()
	defer meter.mu.Unlock()
	meter.peak = 0
}

const (
	// MinIterations and MaxIterations bound a value that arrives from a client or a
	// stored record. Below the floor the stretch is worthless; above the ceiling one
	// login can ask for minutes of CPU. Both products already agreed on these.
	MinIterations = 100_000
	MaxIterations = 12_000_000

	// keyBytes is the derived secret length, and the PBKDF2 output length.
	keyBytes = 32

	minSaltBytes = 16
	maxSaltBytes = 64
)

// AuthSecret derives the hex login secret for a password, a base64 salt and an iteration
// count, separated by label.
func AuthSecret(password, saltBase64 string, iterations int, label string) (string, error) {
	if label == "" {
		return "", errors.New("derive: label is required, it is the domain separation")
	}
	if iterations < MinIterations || iterations > MaxIterations {
		return "", fmt.Errorf("derive: iterations %d is outside %d-%d", iterations, MinIterations, MaxIterations)
	}
	salt, err := base64.StdEncoding.DecodeString(saltBase64)
	if err != nil {
		return "", fmt.Errorf("derive: salt is not base64: %w", err)
	}
	if len(salt) < minSaltBytes || len(salt) > maxSaltBytes {
		return "", fmt.Errorf("derive: salt is %d bytes, want %d-%d", len(salt), minSaltBytes, maxSaltBytes)
	}

	// Admission is taken after validation and around the stretch alone: a call refused
	// for a bad salt should not have occupied a slot to find that out.
	if err := acquire(); err != nil {
		return "", err
	}
	stretched, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyBytes)
	release()
	if err != nil {
		return "", fmt.Errorf("derive: %w", err)
	}
	out, err := hkdf.Key(sha256.New, stretched, nil, label, keyBytes)
	if err != nil {
		return "", fmt.Errorf("derive: %w", err)
	}
	return hex.EncodeToString(out), nil
}

// MinSyntheticKeyBytes is the floor for the key behind a synthetic salt.
//
// The salt itself is not secret — its job is uniqueness. The key is: an attacker who can
// compute synthetic salts can tell them apart from the random salts real accounts carry,
// which is exactly the account-existence oracle this function exists to close. An empty
// or short key makes every synthetic salt predictable, so it is refused rather than used.
const MinSyntheticKeyBytes = 32

// SyntheticSalt derives a stable per-user login salt for an account that has none, so a
// probe cannot tell a registered username from an unregistered one by whether a salt comes
// back.
//
// The username is lower-cased first: keying anything off the raw string lets one account
// present as many, which quietly multiplies any per-account budget layered on top.
func SyntheticSalt(key []byte, label, username string) (string, error) {
	if len(key) < MinSyntheticKeyBytes {
		return "", fmt.Errorf("derive: synthetic salt key is %d bytes, want at least %d", len(key), MinSyntheticKeyBytes)
	}
	if label == "" {
		return "", errors.New("derive: label is required, it is the domain separation")
	}
	mac := hmac.New(sha256.New, key)
	// NUL separates the label from the username. It is the one byte a username cannot
	// contain, so no username can straddle the boundary and impersonate another.
	mac.Write([]byte(label + "\x00" + strings.ToLower(username)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)[:minSaltBytes]), nil
}
