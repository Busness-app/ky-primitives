package recoveryclient

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
)

// SQLiteSnapshot writes a transactionally consistent copy of the live database to destPath
// through the live connection with VACUUM INTO. Copying the database file is not a backup in
// WAL mode: every commit still in the -wal is missing from the copy, silently. destPath must
// not exist; the caller owns the directory it lands in (a 0700 scratch dir, removed after
// sealing). Works with any driver that speaks SQLite; the lib has none, so the product's
// tests are where the row-in-the-WAL case is proven.
func SQLiteSnapshot(ctx context.Context, db *sql.DB, destPath string) error {
	if db == nil {
		return errors.New("recoveryclient: snapshot requires a live database handle")
	}
	if _, err := os.Stat(destPath); err == nil {
		return fmt.Errorf("recoveryclient: snapshot target %s already exists", destPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", destPath); err != nil {
		return fmt.Errorf("recoveryclient: VACUUM INTO failed: %w", err)
	}
	info, err := os.Stat(destPath)
	if err != nil {
		return fmt.Errorf("recoveryclient: snapshot not written: %w", err)
	}
	if info.Size() == 0 {
		return errors.New("recoveryclient: snapshot is empty")
	}
	return nil
}
