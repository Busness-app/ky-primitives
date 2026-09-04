package capsule

import (
	"errors"
	"testing"
)

func TestContainerSizeLimit(t *testing.T) {
	if err := checkContainerSize("container", MaxContainerBytes); err != nil {
		t.Fatalf("limit rejected: %v", err)
	}
	if err := checkContainerSize("container", MaxContainerBytes+1); !errors.Is(err, ErrCapsuleTooLarge) {
		t.Fatalf("over limit: got %v, want ErrCapsuleTooLarge", err)
	}
}
