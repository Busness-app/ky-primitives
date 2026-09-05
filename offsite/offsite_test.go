package offsite

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndKey(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		kind any
	}{
		{"file", Config{URL: "file:///var/backups"}, &localTarget{}},
		{"s3", Config{URL: "s3://bucket/prefix", AccessKey: "key", Secret: "secret"}, &s3Target{}},
		{"sftp", Config{URL: "sftp://ky@example.test/vault", Secret: "secret", HostKey: "SHA256:x"}, &sftpTarget{}},
		{"smb", Config{URL: "smb://nas.test/share/vault", AccessKey: `DOMAIN\ky`, Secret: "secret"}, &smbTarget{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.cfg)
			if err != nil {
				t.Fatal(err)
			}
			switch tt.kind.(type) {
			case *localTarget:
				if _, ok := got.(*localTarget); !ok {
					t.Fatalf("got %T", got)
				}
			case *s3Target:
				if _, ok := got.(*s3Target); !ok {
					t.Fatalf("got %T", got)
				}
			case *sftpTarget:
				if target, ok := got.(*sftpTarget); !ok {
					t.Fatalf("got %T", got)
				} else if target.dir != "vault" {
					t.Fatalf("SFTP dir = %q, want account-relative vault", target.dir)
				}
			case *smbTarget:
				if _, ok := got.(*smbTarget); !ok {
					t.Fatalf("got %T", got)
				}
			}
		})
	}

	c := Config{URL: "sftp://alice@example.test/vault", AccessKey: "alice", Secret: "hunter2", HostKey: "SHA256:secret"}
	key := Key(c)
	if key == "" || strings.Contains(key, "alice") || strings.Contains(key, c.Secret) || strings.Contains(key, c.HostKey) {
		t.Fatalf("credential-free key = %q", key)
	}
	c.Secret = "rotated"
	if Key(c) != key {
		t.Fatal("credential rotation changed target identity")
	}
}

func TestParseRejectsCredentialsInURLsAndIncompleteTargets(t *testing.T) {
	bad := []Config{
		{URL: "https://example.test"},
		{URL: "file://server/path"},
		{URL: "file:///tmp/x", Secret: "x"},
		{URL: "s3://user:pw@bucket/x", AccessKey: "key", Secret: "secret"},
		{URL: "s3://bucket/x", AccessKey: "key"},
		{URL: "sftp://user:pw@host/x", Secret: "secret"},
		{URL: "sftp://host/x", Secret: "secret"},
		{URL: "smb://user:pw@host/share", AccessKey: "user", Secret: "secret"},
		{URL: "smb://host", AccessKey: "user", Secret: "secret"},
		{URL: "file:///tmp/x?secret=y"},
	}
	for _, cfg := range bad {
		if target, err := Parse(cfg); err == nil {
			t.Errorf("Parse(%q) = %T, want error", cfg.URL, target)
		}
	}
}

func TestParseErrorDoesNotRepeatMalformedURLCredentials(t *testing.T) {
	const credential = "do-not-log-this"
	_, err := Parse(Config{URL: "sftp://user:" + credential + "%zz@host/path", Secret: "other"})
	if err == nil || strings.Contains(err.Error(), credential) {
		t.Fatalf("error = %q", err)
	}
}

func TestLocalTargetContract(t *testing.T) {
	dir := t.TempDir()
	target, err := Parse(Config{URL: "file://" + filepath.ToSlash(dir)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := target.Put(ctx, "nested/object", strings.NewReader("first"), 5); err != nil {
		t.Fatal(err)
	}
	if err := target.Put(ctx, "nested/object", strings.NewReader("second"), 6); err != nil {
		t.Fatal(err)
	}
	r, err := target.Get(ctx, "nested/object")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	if closeErr := r.Close(); err == nil {
		err = closeErr
	}
	if err != nil || string(raw) != "second" {
		t.Fatalf("Get = %q, %v", raw, err)
	}
	info, err := os.Stat(filepath.Join(dir, "nested", "object"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, err = %v", info.Mode().Perm(), err)
	}
	if _, err := target.Get(ctx, "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing error = %v", err)
	}
	if err := target.Test(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, pingName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("probe remained: %v", err)
	}
}

func TestTargetsRejectUnsafeNames(t *testing.T) {
	target := &localTarget{dir: t.TempDir()}
	for _, name := range []string{"", "/absolute", "../escape", "a/../b", "a//b", `a\b`, "."} {
		if err := target.Put(context.Background(), name, strings.NewReader("x"), 1); err == nil {
			t.Errorf("Put accepted %q", name)
		}
	}
}
