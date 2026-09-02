// Package recoverycode generates and matches the one-time codes that let a user back into
// an account when every other factor is gone.
//
// The suite issued three strengths for the same job. ky_server_base, gridlock-server and
// kysignon-server produce 8 symbols over a 32-symbol alphabet — 40 bits — and store them
// as a bare SHA-256, which is searchable offline by anyone who reads the store, and which
// bypasses every other factor on the account. kypost-server produces 12 symbols and
// stores them under scrypt. This package issues 12.
//
// Hashing and storage stay with the caller: the products disagree about the hash for
// reasons this package cannot settle, and the codes are not what diverged dangerously.
// What is here is the generation, the normalisation both sides of a comparison must
// agree on, and a lookup that does not leak which entry matched.
package recoverycode

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"strings"
)

// Alphabet has exactly 32 symbols, so a random byte modulo its length is unbiased. It is
// lowercase because codes are copied and pasted, and Normalize folds case anyway.
const Alphabet = "0123456789abcdefghijklmnopqrstuv"

const (
	// symbols is 12 over a 32-symbol alphabet: 60 bits.
	symbols   = 12
	groupSize = 4
	maxCodes  = 1000
)

// Generate returns n distinct codes formatted xxxx-xxxx-xxxx.
func Generate(n int) ([]string, error) {
	if n < 1 || n > maxCodes {
		return nil, fmt.Errorf("recoverycode: count %d is outside 1-%d", n, maxCodes)
	}
	codes := make([]string, 0, n)
	seen := make(map[string]bool, n)
	for len(codes) < n {
		raw := make([]byte, symbols)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("recoverycode: %w", err)
		}
		var b strings.Builder
		for i, v := range raw {
			if i > 0 && i%groupSize == 0 {
				b.WriteByte('-')
			}
			b.WriteByte(Alphabet[int(v)%len(Alphabet)])
		}
		code := b.String()
		// A repeat would give one slot two lives at 60 bits; the draw costs nothing.
		if seen[code] {
			continue
		}
		seen[code] = true
		codes = append(codes, code)
	}
	return codes, nil
}

// Normalize reduces a code to the form that is hashed and compared. A user types the
// separators, or does not, in whichever case their keyboard was in.
func Normalize(code string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(code)) {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Match returns the index of the stored hash equal to candidate.
//
// It compares every entry rather than returning at the first hit. ky_server_base's redeem
// loop breaks on match, so its timing reports where in the list the code sat; the
// comparison itself is constant-time here as well.
//
// An empty stored entry is a slot already redeemed and never matches, so a caller can
// blank a slot in place instead of removing it. Removing renumbers the list, which is how
// two concurrent redemptions lose one another's write.
func Match(candidate string, hashes []string) (int, bool) {
	if candidate == "" {
		return 0, false
	}
	found := -1
	for i, h := range hashes {
		if h == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(h), []byte(candidate)) == 1 && found < 0 {
			found = i
		}
	}
	if found < 0 {
		return 0, false
	}
	return found, true
}
