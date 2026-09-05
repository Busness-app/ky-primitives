package offsite

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type localTarget struct{ dir string }

func (t *localTarget) Put(ctx context.Context, name string, r io.Reader, _ int64) error {
	name, err := cleanName(name)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	final := filepath.Join(t.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(final), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(final), ".ky-offsite-*.part")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := io.Copy(f, &contextReader{ctx: ctx, r: r}); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("offsite: replace local object: %w", err)
	}
	return nil
}

func (t *localTarget) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	name, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return os.Open(filepath.Join(t.dir, filepath.FromSlash(name)))
}

func (t *localTarget) Test(ctx context.Context) error {
	if err := t.Put(ctx, pingName, strings.NewReader("ping"), 4); err != nil {
		return err
	}
	return os.Remove(filepath.Join(t.dir, pingName))
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
