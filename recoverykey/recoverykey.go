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
)

// KEM is the one key encapsulation this package uses. Exported so a test can name it; there
// is no other reason to call it.
func KEM() hpke.KEM { return hpke.MLKEM768X25519() }

// PrivateKey is the recovery private key. It exists in memory during the ceremony that
// splits it and during a restore that combines it, and nowhere else.
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
	k, err := KEM().GenerateKey()
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
	k, err := KEM().NewPrivateKey(seed)
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
	k, err := KEM().NewPublicKey(b)
	if err != nil {
		return PublicKey{}, fmt.Errorf("recoverykey: %w", err)
	}
	return PublicKey{key: k}, nil
}

// Seed returns a copy of the 32 bytes that are split into custodian shares. Nothing else
// about this key is ever split.
func (k PrivateKey) Seed() []byte { return bytes.Clone(k.seed[:]) }

// Public returns the matching public key.
func (k PrivateKey) Public() PublicKey { return PublicKey{key: k.key.PublicKey()} }

// HPKE exposes the underlying key for capsule.Open. It is the same value crypto/hpke
// returned; nothing here is more secret than the PrivateKey already was.
func (k PrivateKey) HPKE() hpke.PrivateKey { return k.key }

// Bytes returns a copy of the 1216-byte encoding, what keyfile.Store persists.
func (p PublicKey) Bytes() []byte { return bytes.Clone(p.key.Bytes()) }

// ID is the lowercase hex SHA-256 of Bytes. It is what a capsule names, what kyrecovery
// pins, and what a custodian writes on a card.
func (p PublicKey) ID() string {
	sum := sha256.Sum256(p.key.Bytes())
	return hex.EncodeToString(sum[:])
}

// HPKE exposes the underlying key for capsule.Seal.
func (p PublicKey) HPKE() hpke.PublicKey { return p.key }
