package recoveryclient

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The lib carries no SQLite driver, so the row-in-the-WAL case is proven in each product's
// tests; here only the guards around the VACUUM are pinned.
func TestSQLiteSnapshotGuards(t *testing.T) {
	if err := SQLiteSnapshot(context.Background(), nil, filepath.Join(t.TempDir(), "s.db")); err == nil {
		t.Fatal("nil handle accepted")
	}
	existing := filepath.Join(t.TempDir(), "s.db")
	_ = os.WriteFile(existing, []byte("x"), 0600)
	if err := SQLiteSnapshot(context.Background(), nil, existing); err == nil {
		t.Fatal("existing target accepted")
	}
}
