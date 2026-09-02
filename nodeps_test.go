package kyprimitives

import (
	"os"
	"strings"
	"testing"
)

// The suite's products carry very different dependency trees — kysignon-server's
// architecture rests on three direct dependencies — and a shared module heavier than the
// standard library is one none of them can take. "No dependencies, ever" is the whole
// reason this module can be imported everywhere, so it is enforced rather than promised.
func TestModuleHasNoDependencies(t *testing.T) {
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(raw), "\n") {
		field, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch field {
		case "require", "replace", "exclude":
			t.Errorf("go.mod:%d declares a dependency: %s", i+1, strings.TrimSpace(line))
		}
	}
}
