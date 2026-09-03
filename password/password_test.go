package password

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	encoded, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify("correct horse battery staple", encoded)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	ok, err = Verify("Correct horse battery staple", encoded)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a wrong password verified")
	}
}

func TestHashIsSaltedPerCall(t *testing.T) {
	a, err := Hash("same")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash("same")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes of one password are identical, so the salt is not random")
	}
}

func TestHashUsesTheDeclaredParameters(t *testing.T) {
	encoded, err := Hash("x")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("encoded form is %q", encoded)
	}
	if n := len(strings.Split(encoded, "$")); n != 6 {
		t.Fatalf("PHC string has %d segments", n)
	}
}

// ky_server_base and gridlock-server fall back to their compiled defaults when the
// parameter segment does not parse, so a hash with an attacker-chosen or corrupt
// parameter line is verified against something other than what it claims.
func TestVerifyRejectsMalformedHashRatherThanUsingDefaults(t *testing.T) {
	good, err := Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, "$")
	for _, tc := range []struct{ name, encoded string }{
		{"empty", ""},
		{"not phc", "deadbeef"},
		{"wrong algorithm", "$argon2i$v=19$m=65536,t=3,p=4$" + parts[4] + "$" + parts[5]},
		{"wrong version", "$argon2id$v=16$m=65536,t=3,p=4$" + parts[4] + "$" + parts[5]},
		{"unparseable params", "$argon2id$v=19$m=abc,t=3,p=4$" + parts[4] + "$" + parts[5]},
		{"missing params", "$argon2id$v=19$$" + parts[4] + "$" + parts[5]},
		{"truncated", strings.Join(parts[:5], "$")},
		{"bad salt base64", "$argon2id$v=19$m=65536,t=3,p=4$!!!!$" + parts[5]},
		{"bad hash base64", "$argon2id$v=19$m=65536,t=3,p=4$" + parts[4] + "$!!!!"},
		{"extra segment", good + "$extra"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := Verify("pw", tc.encoded)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if ok {
				t.Fatal("a malformed hash verified")
			}
		})
	}
}

// A stored hash is attacker-controlled wherever the store is. One asking for terabytes
// OOM-kills the process on the next login attempt.
func TestVerifyRejectsParametersOutsideBounds(t *testing.T) {
	good, err := Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, "$")
	tail := "$" + parts[4] + "$" + parts[5]
	for _, params := range []string{
		"m=4294967295,t=3,p=4", // asks for 4 TiB
		"m=1,t=3,p=4",          // below the floor
		"m=65536,t=0,p=4",
		"m=65536,t=999,p=4",
		"m=65536,t=3,p=0",
		"m=65536,t=3,p=255",
	} {
		t.Run(params, func(t *testing.T) {
			ok, err := Verify("pw", "$argon2id$v=19$"+params+tail)
			if err == nil || ok {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestVerifyRejectsShortSaltAndHash(t *testing.T) {
	for _, tc := range []struct{ name, encoded string }{
		{"short salt", "$argon2id$v=19$m=65536,t=3,p=4$AAAA$" + strings.Repeat("A", 43)},
		{"short hash", "$argon2id$v=19$m=65536,t=3,p=4$" + strings.Repeat("A", 22) + "$AAAA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ok, err := Verify("pw", tc.encoded); err == nil || ok {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestNeedsRehash(t *testing.T) {
	current, err := Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	need, err := NeedsRehash(current)
	if err != nil {
		t.Fatal(err)
	}
	if need {
		t.Fatal("a hash at the current parameters wants a rehash")
	}

	parts := strings.Split(current, "$")
	weaker := "$argon2id$v=19$m=16384,t=1,p=4$" + parts[4] + "$" + parts[5]
	need, err = NeedsRehash(weaker)
	if err != nil {
		t.Fatal(err)
	}
	if !need {
		t.Fatal("a hash below the current parameters does not want a rehash")
	}

	// A hash this package did not write is not stale, it is not ours: no error, no
	// rehash. Verify still refuses "garbage" outright.
	need, err = NeedsRehash("garbage")
	if err != nil {
		t.Fatal(err)
	}
	if need {
		t.Fatal("NeedsRehash flagged a foreign format as wanting a rehash")
	}
}

// A hash minted under weaker parameters must still verify, so a deployment can rehash on
// next login instead of locking everyone out.
func TestVerifyAcceptsAWeakerButValidHash(t *testing.T) {
	encoded, err := hashWith("pw", Params{Memory: 16384, Time: 1, Threads: 4})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify("pw", encoded)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestHashRejectsAnEmptyPassword(t *testing.T) {
	if _, err := Hash(""); err == nil {
		t.Fatal("an empty password was hashed")
	}
}

// 64 MiB per derivation makes an unbounded login endpoint an OOM primitive. kynotes-server
// bounds it but blocks forever, so overload is indistinguishable from a wrong password.
func TestConcurrentHashingIsBounded(t *testing.T) {
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Hash("pw"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, ErrBusy) {
			t.Fatalf("got %v, want nil or ErrBusy", err)
		}
	}
}

func TestVerifyIsNotVulnerableToAnEmptyStoredHash(t *testing.T) {
	// A user row with no hash must never authenticate, whatever is supplied.
	for _, stored := range []string{"", "$", "$$$$$"} {
		if ok, _ := Verify("", stored); ok {
			t.Fatalf("empty password verified against stored %q", stored)
		}
	}
}
