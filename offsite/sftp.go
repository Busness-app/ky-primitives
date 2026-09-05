package offsite

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// UnknownHostKeyError reports the fingerprint an operator must verify and pin.
type UnknownHostKeyError struct{ Fingerprint string }

func (e *UnknownHostKeyError) Error() string {
	return "offsite: host key not pinned; server presented " + e.Fingerprint
}

type sftpTarget struct {
	addr, user, secret, dir, hostKey string
	timeout                          time.Duration
}

func (t *sftpTarget) auth() (ssh.AuthMethod, error) {
	if block, _ := pem.Decode([]byte(t.secret)); block != nil {
		signer, err := ssh.ParsePrivateKey([]byte(t.secret))
		if err != nil {
			return nil, fmt.Errorf("offsite: private key: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	}
	return ssh.Password(t.secret), nil
}

func (t *sftpTarget) dial(ctx context.Context) (*sftp.Client, func(), error) {
	auth, err := t.auth()
	if err != nil {
		return nil, nil, err
	}
	cfg := &ssh.ClientConfig{
		User: t.user,
		Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint := ssh.FingerprintSHA256(key)
			if t.hostKey == "" {
				return &UnknownHostKeyError{Fingerprint: fingerprint}
			}
			if fingerprint != t.hostKey {
				return fmt.Errorf("offsite: host key mismatch: pinned %s, server presented %s", t.hostKey, fingerprint)
			}
			return nil
		},
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	cleanup := func() { stop(); _ = conn.Close() }
	sconn, chans, reqs, err := ssh.NewClientConn(conn, t.addr, cfg)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	sshClient := ssh.NewClient(sconn, chans, reqs)
	client, err := sftp.NewClient(sshClient)
	if err != nil {
		_ = sshClient.Close()
		cleanup()
		return nil, nil, err
	}
	return client, func() { _ = client.Close(); _ = sshClient.Close(); cleanup() }, nil
}

func (t *sftpTarget) Put(ctx context.Context, name string, r io.Reader, _ int64) error {
	name, err := cleanName(name)
	if err != nil {
		return err
	}
	ctx, cancel := budget(ctx, t.timeout)
	defer cancel()
	client, cleanup, err := t.dial(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if t.dir != "" {
		if err := client.MkdirAll(t.dir); err != nil {
			return err
		}
	}
	final, tmp := path.Join(t.dir, name), path.Join(t.dir, name)+".part"
	if err := client.MkdirAll(path.Dir(final)); err != nil {
		return err
	}
	f, err := client.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, &contextReader{ctx: ctx, r: r}); err != nil {
		_ = f.Close()
		_ = client.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = client.Remove(tmp)
		return err
	}
	if err := client.PosixRename(tmp, final); err != nil {
		_ = client.Remove(tmp)
		return err
	}
	return nil
}

func (t *sftpTarget) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	name, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := budget(ctx, t.timeout)
	client, cleanup, err := t.dial(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	f, err := client.Open(path.Join(t.dir, name))
	if err != nil {
		cleanup()
		cancel()
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return &sessionReadCloser{ReadCloser: f, cleanup: cleanup, cancel: cancel}, nil
}

func (t *sftpTarget) Test(ctx context.Context) error {
	ctx, cancel := budget(ctx, t.timeout)
	defer cancel()
	client, cleanup, err := t.dial(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if t.dir != "" {
		if err := client.MkdirAll(t.dir); err != nil {
			return err
		}
	}
	probe := path.Join(t.dir, pingName)
	f, err := client.Create(probe)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte("ping")); err != nil {
		_ = f.Close()
		_ = client.Remove(probe)
		return err
	}
	if err := f.Close(); err != nil {
		_ = client.Remove(probe)
		return err
	}
	return client.Remove(probe)
}

type sessionReadCloser struct {
	io.ReadCloser
	cleanup func()
	cancel  context.CancelFunc
	once    sync.Once
}

func (c *sessionReadCloser) Close() (err error) {
	c.once.Do(func() {
		err = c.ReadCloser.Close()
		c.cleanup()
		c.cancel()
	})
	return err
}
