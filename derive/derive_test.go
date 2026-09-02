package derive

import (
	"strings"
	"testing"
)

// saltB64 is base64 of the 16 ASCII bytes "0123456789abcdef".
const saltB64 = "MDEyMzQ1Njc4OWFiY2RlZg=="

// These vectors were produced by running kynotes-server's DeriveAuthSecret, not by
// running this package. They are the contract: a browser and two Go servers already
// compute this value, and a migration that changes any byte locks every user out.
func TestMatchesTheExistingImplementation(t *testing.T) {
	for _, tc := range []struct {
		iterations int
		want       string
	}{
		{100000, "b9eb85992f985b432a3feaf4f5ea0b7b7960a5da42c640a3b9d93a83fc5bef1d"},
		{250000, "85a6f13c7986c251b847362680291f26faa332370a7c82fad8455aaf37ca55a5"},
	} {
		got, err := AuthSecret("correct horse battery staple", saltB64, tc.iterations, "kynotes/auth/v1")
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("iterations %d:\n got %s\nwant %s", tc.iterations, got, tc.want)
		}
	}
}

// Produced by running kynotes-server's SyntheticLoginSalt, not this package.
const synthKey = "0123456789abcdef0123456789abcdef"

func TestSyntheticSaltMatchesTheExistingImplementation(t *testing.T) {
	got, err := SyntheticSalt([]byte(synthKey), "login-salt/v1", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if want := "UDuT7+xmxlasLhMfxQYnzg=="; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestSyntheticSaltFoldsCase(t *testing.T) {
	a, err := SyntheticSalt([]byte(synthKey), "login-salt/v1", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	b, err := SyntheticSalt([]byte(synthKey), "login-salt/v1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("the same username in two cases produced two salts, so a lockout budget splits")
	}
}

// Finding 4.3: a missing configuration value made every synthetic salt predictable, and
// the function reported success.
func TestSyntheticSaltRejectsAWeakKeyOrEmptyLabel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   []byte
		label string
	}{
		{"nil key", nil, "login-salt/v1"},
		{"empty key", []byte{}, "login-salt/v1"},
		{"short key", []byte("pairing-secret"), "login-salt/v1"},
		{"one byte under", make([]byte, MinSyntheticKeyBytes-1), "login-salt/v1"},
		{"empty label", []byte(synthKey), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SyntheticSalt(tc.key, tc.label, "alice")
			if err == nil {
				t.Fatalf("accepted, returning %q", got)
			}
			if got != "" {
				t.Fatalf("returned %q alongside an error", got)
			}
		})
	}
}

// The label is domain separation, so two products deriving from one password must not
// land on the same secret.
func TestLabelSeparatesProducts(t *testing.T) {
	a, err := AuthSecret("pw", saltB64, 100000, "kynotes/auth/v1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := AuthSecret("pw", saltB64, 100000, "kypost/auth/v1")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two labels produced one secret")
	}
}

func TestAuthSecretRejectsBadParameters(t *testing.T) {
	for _, tc := range []struct {
		name       string
		salt       string
		iterations int
		label      string
	}{
		{"iterations below floor", saltB64, MinIterations - 1, "l"},
		{"iterations above ceiling", saltB64, MaxIterations + 1, "l"},
		{"salt not base64", "!!!!", 100000, "l"},
		{"salt too short", "MDEyMzQ1Njc=", 100000, "l"},
		{"salt too long", strings.Repeat("QUFB", 30), 100000, "l"},
		{"empty label", saltB64, 100000, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := AuthSecret("pw", tc.salt, tc.iterations, tc.label); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

// A caller that forgets to bound iterations lets a stored or client-supplied value ask
// for hours of CPU per login. The bounds are the reason this is a package and not a call.
func TestIterationBoundsAreTheOnesTheSuiteAgreedOn(t *testing.T) {
	if MinIterations != 100000 {
		t.Errorf("MinIterations is %d", MinIterations)
	}
	if MaxIterations != 12000000 {
		t.Errorf("MaxIterations is %d", MaxIterations)
	}
}
