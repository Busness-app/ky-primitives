package recoveryclient

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LocalCopy is one sealed capsule in the local backup directory.
type LocalCopy struct {
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
}

// localPrefix scopes this instance's files in the backup directory: only names carrying it
// are listed or pruned, so capsules the operator put there by hand, or another service's,
// are never touched.
func localPrefix(appName string) string {
	return FilenameSafe(appName) + "-"
}

// WriteLocalCopy stores a sealed capsule as <app>-<capsule-id>.kycap in dir and prunes this
// instance's oldest beyond keep. The bytes are sealed to the suite key, so the directory
// needs no more protection than any other file the operator keeps; 0600 anyway. The write
// goes through a temp file and rename so a crash never leaves a truncated .kycap that looks
// like a backup.
func WriteLocalCopy(dir, appName, capsuleID string, raw []byte, keep int) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("backup dir: %w", err)
	}
	final := filepath.Join(dir, localPrefix(appName)+FilenameSafe(capsuleID)+".kycap")
	tmp, err := os.CreateTemp(dir, ".kycap-*")
	if err != nil {
		return "", fmt.Errorf("backup dir: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", err
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		cleanup()
		return "", err
	}
	if err := os.Rename(tmpName, final); err != nil {
		cleanup()
		return "", err
	}
	copies, err := ListLocalCopies(dir, appName)
	if err != nil {
		return final, err
	}
	for _, c := range copies[min(keep, len(copies)):] {
		if err := os.Remove(filepath.Join(dir, c.Name)); err != nil && !os.IsNotExist(err) {
			return final, fmt.Errorf("prune %s: %w", c.Name, err)
		}
	}
	return final, nil
}

// ListLocalCopies returns this instance's .kycap files in dir, newest first. A missing
// directory is an empty list: nothing has been written yet.
func ListLocalCopies(dir, appName string) ([]LocalCopy, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []LocalCopy
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), localPrefix(appName)) || !strings.HasSuffix(e.Name(), ".kycap") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, LocalCopy{Name: e.Name(), SizeBytes: info.Size(), CreatedAt: info.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
