// Package recoverykey is the suite's recovery keypair: the one public key every product
// seals its backups to, and the private key that exists only while it is being split into
// custodian shares and while a restore combines them.
//
// The KEM is X-Wing (ML-KEM-768 with X25519), through crypto/hpke. A backup is the artefact
// most likely to still matter when a recorded ciphertext is attacked, so the KEM is the
// one place this library pays for post-quantum security.
//
// Every crypto/hpke KEM rebuilds its private key from a 32-byte seed, and the seed is the
// only thing this package ever hands to shamir. Whatever the KEM, a custodian card carries
// 32 bytes.
package recoverykey

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// SeedBytes is the length of the private key seed, the thing that is split.
	SeedBytes = 32
	// PublicKeyBytes is an X-Wing public key: ML-KEM-768 encapsulation key plus X25519 point.
	PublicKeyBytes = 1184 + 32
	// EncapsulationBytes is an X-Wing encapsulated key: ML-KEM-768 ciphertext plus X25519 point.
	EncapsulationBytes = 1088 + 32
)

var (
	// ErrSeedLength reports a seed that is not exactly SeedBytes long.
	ErrSeedLength = errors.New("recoverykey: seed must be exactly 32 bytes")
	// ErrPublicKeyLength reports public key bytes that are not exactly PublicKeyBytes long.
	ErrPublicKeyLength = errors.New("recoverykey: public key must be exactly 1216 bytes")
	// ErrUninitializedKey reports a zero-value PrivateKey or PublicKey used as if it were real.
	ErrUninitializedKey = errors.New("recoverykey: zero-value key; use Generate, FromSeed or ParsePublicKey")
)

// kem is the one key encapsulation this package uses.
func kem() hpke.KEM { return hpke.MLKEM768X25519() }

// PrivateKey is the recovery private key. It exists in memory during the ceremony that
// splits it and during a restore that combines it, and nowhere else.
//
// It cannot be erased from a running Go process: value receivers, Seed's copies, the
// embedded HPKE key's own state and the garbage collector all keep the seed recoverable
// from a core dump or a swap page for the process lifetime. The ceremony therefore runs on
// a dedicated ephemeral host with swap off and core dumps disabled, and that host is
// destroyed after Split returns. The host is what gets thrown away, not the bytes.
type PrivateKey struct {
	seed [SeedBytes]byte
	key  hpke.PrivateKey
}

// PublicKey is what every product holds and seals to.
type PublicKey struct {
	key hpke.PublicKey
}

// Generate makes a fresh keypair.
func Generate() (PrivateKey, error) {
	k, err := kem().GenerateKey()
	if err != nil {
		return PrivateKey{}, fmt.Errorf("recoverykey: %w", err)
	}
	// A hybrid key made by GenerateKey carries its seed; Bytes returns it. Going through
	// FromSeed rather than storing k directly means there is one constructor.
	seed, err := k.Bytes()
	if err != nil {
		return PrivateKey{}, fmt.Errorf("recoverykey: %w", err)
	}
	return FromSeed(seed)
}

// FromSeed rebuilds the private key from its 32-byte seed. It is what Combine hands back.
func FromSeed(seed []byte) (PrivateKey, error) {
	if len(seed) != SeedBytes {
		return PrivateKey{}, fmt.Errorf("%w: got %d", ErrSeedLength, len(seed))
	}
	k, err := kem().NewPrivateKey(seed)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("recoverykey: %w", err)
	}
	var p PrivateKey
	copy(p.seed[:], seed)
	p.key = k
	return p, nil
}

// ParsePublicKey reads the bytes keyfile.Load or a pairing message hands back.
func ParsePublicKey(b []byte) (PublicKey, error) {
	if len(b) != PublicKeyBytes {
		return PublicKey{}, fmt.Errorf("%w: got %d", ErrPublicKeyLength, len(b))
	}
	k, err := kem().NewPublicKey(b)
	if err != nil {
		return PublicKey{}, fmt.Errorf("recoverykey: %w", err)
	}
	return PublicKey{key: k}, nil
}

// Seed returns a copy of the 32 bytes that are split into custodian shares. Nothing else
// about this key is ever split.
func (k PrivateKey) Seed() []byte { return bytes.Clone(k.seed[:]) }

// Public returns the matching public key, or the zero PublicKey if k is zero.
func (k PrivateKey) Public() PublicKey {
	if k.IsZero() {
		return PublicKey{}
	}
	return PublicKey{key: k.key.PublicKey()}
}

// HPKE exposes the underlying key for capsule.Open. It is the same value crypto/hpke
// returned; nothing here is more secret than the PrivateKey already was. It returns nil
// if k is zero.
func (k PrivateKey) HPKE() hpke.PrivateKey { return k.key }

// IsZero reports whether k is the zero value, holding no key. Every constructor
// (Generate, FromSeed, Combine) produces a non-zero PrivateKey.
func (k PrivateKey) IsZero() bool { return k.key == nil }

// Bytes returns a copy of the 1216-byte encoding, what keyfile.Store persists, or nil if
// p is zero.
func (p PublicKey) Bytes() []byte {
	if p.IsZero() {
		return nil
	}
	return bytes.Clone(p.key.Bytes())
}

// ID is the lowercase hex SHA-256 of Bytes. It is what a capsule names, what kyrecovery
// pins, and what a custodian writes on a card. It returns "" if p is zero.
func (p PublicKey) ID() string {
	b := p.Bytes()
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HPKE exposes the underlying key for capsule.Seal. It returns nil if p is zero.
func (p PublicKey) HPKE() hpke.PublicKey { return p.key }

// IsZero reports whether p is the zero value, holding no key. Every constructor
// (Generate, ParsePublicKey, PrivateKey.Public) produces a non-zero PublicKey.
func (p PublicKey) IsZero() bool { return p.key == nil }
