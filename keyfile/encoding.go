package keyfile

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Encoding is how a key is spelled on disk.
//
// Hex is this package's default and the suite's preference: an operator can read it, copy
// it and diff it without a tool. Raw and Base64 exist because four products already wrote
// their key files that way, and a package that cannot read them is a package they cannot
// adopt.
type Encoding int

const (
	// Hex is lowercase hex, optionally with surrounding whitespace.
	Hex Encoding = iota
	// Raw is the key bytes themselves, with nothing around them.
	Raw
	// Base64 is standard base64, optionally with surrounding whitespace.
	Base64
)

func (e Encoding) decode(b []byte) ([]byte, error) {
	switch e {
	case Raw:
		return b, nil
	case Base64:
		return base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	case Hex:
		return hex.DecodeString(strings.TrimSpace(string(b)))
	}
	return nil, fmt.Errorf("keyfile: unknown encoding %d", int(e))
}

func (e Encoding) encode(key []byte) []byte {
	switch e {
	case Raw:
		return key
	case Base64:
		return []byte(base64.StdEncoding.EncodeToString(key) + "\n")
	default:
		return []byte(hex.EncodeToString(key) + "\n")
	}
}

// FromEnv reads a key from an environment variable, accepting hex or base64.
//
// It returns false when the variable is unset or blank. A variable that is set to
// something else but does not decode to exactly size bytes is an error, never a miss:
// falling through to the file there would start the process under a key the operator did
// not choose and believes they overrode.
//
// This exists because four products in the suite check an environment variable before the
// file, and doing that outside this package means the env-supplied key skips every check
// the file-supplied one gets.
func FromEnv(name string, size int) ([]byte, bool, error) {
	if size < minSize {
		return nil, false, fmt.Errorf("keyfile: size %d is below the %d-byte floor", size, minSize)
	}

	raw, ok := os.LookupEnv(name)
	trimmed := strings.TrimSpace(raw)
	if !ok || trimmed == "" {
		return nil, false, nil
	}

	for _, enc := range []Encoding{Hex, Base64} {
		key, err := enc.decode([]byte(trimmed))
		if err == nil && len(key) == size {
			return key, true, nil
		}
	}
	return nil, true, fmt.Errorf("keyfile: %s is set but is not %d bytes of hex or base64", name, size)
}
