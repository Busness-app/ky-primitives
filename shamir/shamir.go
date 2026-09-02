// Package shamir splits a secret into custodian shares and reconstructs it.
//
// The suite carried two implementations over two different GF(2^8) fields — 0x11d in
// ky_server_base, gridlock-server and kysignon-server, 0x11b in kyrecovery-server. They
// silently reconstruct different secrets: 63232 of the 65536 products in their
// multiplication tables disagree. It stayed hidden because shares 1, 2 and 3 make every
// Lagrange coefficient 1, so the combine degenerates to XOR and agrees in any field, and
// those are the shares a round-trip test reaches for first.
//
// This package uses 0x11b, the AES field, and pins it with golden vectors.
//
// Arithmetic here is branch-free and table-free. Both predecessors indexed exp/log
// tables with share bytes, which are the secret; this one multiplies with shifts and
// masks and inverts by exponentiation, so no memory access depends on a secret value.
// It is slower and a capsule split is not a hot path.
package shamir

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	// ErrNotEnoughShares reports fewer than two shares handed to Combine. It cannot
	// report fewer than the threshold: a share carries no record of what the threshold
	// was, so too few shares reconstruct a wrong secret with no error. Bind a hash of
	// the plaintext alongside — the capsule package's payload hash is that check.
	ErrNotEnoughShares = errors.New("shamir: at least two shares are required")
	// ErrDuplicateIndex reports shares repeating an index, which makes a Lagrange
	// denominator zero.
	ErrDuplicateIndex = errors.New("shamir: shares repeat an index")
	// ErrShareIndex reports a share at index 0, the point the secret itself sits on.
	ErrShareIndex = errors.New("shamir: share index must be 1-255")
	// ErrShareLength reports shares of differing or zero length.
	ErrShareLength = errors.New("shamir: shares differ in length")
	// ErrMalformedShare reports a string that is not a share.
	ErrMalformedShare = errors.New("shamir: share is not index-hex")
)

// Share is one custodian's portion of a secret.
type Share struct {
	Index byte
	Value []byte
}

// String renders a share for a custodian card as "index-hex".
func (s Share) String() string {
	return strconv.Itoa(int(s.Index)) + "-" + hex.EncodeToString(s.Value)
}

// ParseShare reads a share off a custodian card. Surrounding space and uppercase hex are
// accepted because the string is typed in by a human under stress.
func ParseShare(encoded string) (Share, error) {
	parts := strings.Split(strings.TrimSpace(encoded), "-")
	if len(parts) != 2 {
		return Share{}, ErrMalformedShare
	}
	index, err := strconv.Atoi(parts[0])
	if err != nil {
		return Share{}, fmt.Errorf("%w: %v", ErrMalformedShare, err)
	}
	if index < 1 || index > 255 {
		return Share{}, ErrShareIndex
	}
	value, err := hex.DecodeString(parts[1])
	if err != nil {
		return Share{}, fmt.Errorf("%w: %v", ErrMalformedShare, err)
	}
	if len(value) == 0 {
		return Share{}, ErrShareLength
	}
	return Share{Index: byte(index), Value: value}, nil
}

// Split divides secret into total shares, any threshold of which reconstruct it.
func Split(secret []byte, threshold, total int) ([]Share, error) {
	switch {
	case len(secret) == 0:
		return nil, errors.New("shamir: refusing to split an empty secret")
	case threshold < 2:
		return nil, errors.New("shamir: threshold must be at least 2")
	case threshold > total:
		return nil, errors.New("shamir: threshold exceeds the share count")
	case total > 255:
		return nil, errors.New("shamir: at most 255 shares fit in GF(2^8)")
	}

	shares := make([]Share, total)
	for i := range shares {
		shares[i] = Share{Index: byte(i + 1), Value: make([]byte, len(secret))}
	}

	coefficients := make([]byte, threshold)
	for byteIndex, secretByte := range secret {
		coefficients[0] = secretByte
		// A zero leading coefficient drops the polynomial's degree, so fewer shares than
		// promised reconstruct that byte. Resampling costs one draw in 256.
		for {
			if _, err := rand.Read(coefficients[1:]); err != nil {
				return nil, fmt.Errorf("shamir: %w", err)
			}
			if coefficients[threshold-1] != 0 {
				break
			}
		}
		for i := range shares {
			shares[i].Value[byteIndex] = evaluate(coefficients, shares[i].Index)
		}
	}
	return shares, nil
}

// Combine reconstructs a secret by Lagrange interpolation at x=0. Every share given is
// used; passing more than the threshold is correct and passing fewer returns a wrong
// secret rather than an error, for the reason on ErrNotEnoughShares.
func Combine(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, ErrNotEnoughShares
	}
	size := len(shares[0].Value)
	if size == 0 {
		return nil, ErrShareLength
	}
	var seen [256]bool
	for _, s := range shares {
		switch {
		case s.Index == 0:
			return nil, ErrShareIndex
		case seen[s.Index]:
			return nil, ErrDuplicateIndex
		case len(s.Value) != size:
			return nil, ErrShareLength
		}
		seen[s.Index] = true
	}

	// Distinct non-zero indices make every denominator non-zero, so no inverse here can
	// be of zero and Combine cannot divide by zero however malformed its input.
	basis := make([]byte, len(shares))
	for i, si := range shares {
		numerator, denominator := byte(1), byte(1)
		for j, sj := range shares {
			if i == j {
				continue
			}
			numerator = mul(numerator, sj.Index)
			denominator = mul(denominator, si.Index^sj.Index)
		}
		basis[i] = mul(numerator, inverse(denominator))
	}

	secret := make([]byte, size)
	for b := range secret {
		var acc byte
		for i, s := range shares {
			acc ^= mul(s.Value[b], basis[i])
		}
		secret[b] = acc
	}
	return secret, nil
}

// evaluate computes the polynomial at x by Horner's method, constant term first.
func evaluate(coefficients []byte, x byte) byte {
	var y byte
	for i := len(coefficients) - 1; i >= 0; i-- {
		y = mul(y, x) ^ coefficients[i]
	}
	return y
}

// mul multiplies in GF(2^8) mod 0x11b. Branch-free: the conditionals are mask arithmetic
// so neither timing nor memory access depends on a or b.
func mul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		p ^= a & -(b & 1)
		high := a >> 7
		a <<= 1
		a ^= 0x1b & -high
		b >>= 1
	}
	return p
}

// inverse returns a^254, which is a^-1 for every non-zero a, and 0 for 0. The exponent's
// bits are a compile-time constant, so the branch does not depend on a.
func inverse(a byte) byte {
	result, power := byte(1), a
	for e := 0; e < 8; e++ {
		if (254>>e)&1 == 1 {
			result = mul(result, power)
		}
		power = mul(power, power)
	}
	return result
}
