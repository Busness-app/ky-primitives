package kyprimitives

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// allowed is the module's entire dependency budget.
//
// The rule used to be "no dependencies, ever", so that products with minimal trees —
// kypassword-server's go.mod requires nothing at all — could import capsule and shamir
// for free. Argon2 broke it: the suite standardised on it for password hashing, and it is
// not in the standard library and not on a proposal track.
//
// So the budget is x/crypto and the x/sys it drags in, and nothing else. Every other
// package in this module stays standard-library-only; a consumer that only wants capsule
// still compiles none of this, though it does inherit the requirement in its go.mod.
var allowed = map[string]bool{
	"golang.org/x/crypto": true,
	"golang.org/x/sys":    true,
}

var requireLine = regexp.MustCompile(`^([a-zA-Z0-9._~/-]+\.[a-zA-Z0-9._~/-]+)\s+v`)

const selfModule = "github.com/Busness-app/ky-primitives"

// importsOf returns every quoted import path in src that starts with prefix.
func importsOf(src, prefix string) []string {
	var found []string
	for _, chunk := range strings.Split(src, `"`+prefix)[1:] {
		if end := strings.Index(chunk, `"`); end >= 0 {
			found = append(found, prefix+chunk[:end])
		}
	}
	return found
}

func TestModuleDependenciesAreAllowlisted(t *testing.T) {
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(raw), "\n") {
		text := strings.TrimSpace(line)
		if idx := strings.Index(text, "//"); idx >= 0 {
			text = strings.TrimSpace(text[:idx])
		}
		switch {
		case strings.HasPrefix(text, "replace ") || strings.HasPrefix(text, "exclude "):
			t.Errorf("go.mod:%d: %s", i+1, text)
			continue
		case strings.HasPrefix(text, "module ") || strings.HasPrefix(text, "go ") || strings.HasPrefix(text, "toolchain "):
			continue
		}
		text = strings.TrimPrefix(text, "require ")
		m := requireLine.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		if !allowed[m[1]] {
			t.Errorf("go.mod:%d requires %s, which is not in the dependency budget", i+1, m[1])
		}
	}
}

// Only the password package may import outside the standard library. This is the check
// that keeps the budget from spreading once it exists.
func TestOnlyPasswordImportsADependency(t *testing.T) {
	for _, dir := range []string{"capsule", "shamir", "auditchain"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			src, err := os.ReadFile(dir + "/" + e.Name())
			if err != nil {
				t.Fatal(err)
			}
			for _, dep := range []string{"golang.org/x/", "github.com/"} {
				for _, imp := range importsOf(string(src), dep) {
					// The module importing itself is not a dependency.
					if strings.HasPrefix(imp, selfModule) {
						continue
					}
					t.Errorf("%s/%s imports %s; only password may", dir, e.Name(), imp)
				}
			}
		}
	}
}
