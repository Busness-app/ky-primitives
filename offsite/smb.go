package offsite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// ParseSMBEndpoint accepts a bare host, host:port, UNC path, slash path, or
// smb:// URL. Credentials in the endpoint are rejected because endpoints are
// commonly logged and stored in cleartext.
func ParseSMBEndpoint(endpoint, share, dir string) (addr, outShare, outDir string, err error) {
	addr = strings.ReplaceAll(endpoint, "\\", "/")
	if len(addr) >= 6 && strings.EqualFold(addr[:6], "smb://") {
		addr = addr[6:]
	}
	addr = strings.TrimLeft(addr, "/")
	if strings.Contains(addr, "@") {
		return "", "", "", errors.New("offsite: put SMB credentials in AccessKey and Secret, not the endpoint")
	}
	if host, rest, ok := strings.Cut(addr, "/"); ok {
		addr = host
		pathShare, pathDir, _ := strings.Cut(strings.Trim(rest, "/"), "/")
		if share == "" {
			share = pathShare
		}
		if dir == "" {
			dir = pathDir
		}
	}
	if addr == "" {
		return "", "", "", errors.New("offsite: SMB endpoint requires a host")
	}
	if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "445")
	}
	if share == "" || strings.ContainsAny(share, "/\\\x00") || share == "." || share == ".." {
		return "", "", "", errors.New("offsite: SMB endpoint requires a safe share name")
	}
	dir, err = cleanPrefix(dir)
	if err != nil {
		return "", "", "", err
	}
	return addr, share, dir, nil
}

type smbTarget struct {
	addr, share, user, secret, dir string
	timeout                        time.Duration
}

func (t *smbTarget) mount(ctx context.Context) (*smb2.Share, func(), error) {
	domain, user, _ := strings.Cut(t.user, "\\")
	if user == "" {
		domain, user = "", domain
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	cleanup := func() { stop(); _ = conn.Close() }
	dialer := &smb2.Dialer{
		Negotiator: smb2.Negotiator{RequireMessageSigning: true},
		Initiator:  &smb2.NTLMInitiator{User: user, Password: t.secret, Domain: domain},
	}
	session, err := dialer.DialContext(ctx, conn)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	share, err := session.Mount(t.share)
	if err != nil {
		_ = session.Logoff()
		cleanup()
		return nil, nil, fmt.Errorf("offsite: mount SMB share %s: %w", t.share, err)
	}
	return share, func() { _ = share.Umount(); _ = session.Logoff(); cleanup() }, nil
}

func (t *smbTarget) Put(ctx context.Context, name string, r io.Reader, _ int64) error {
	name, err := cleanName(name)
	if err != nil {
		return err
	}
	ctx, cancel := budget(ctx, t.timeout)
	defer cancel()
	share, cleanup, err := t.mount(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	final := path.Join(t.dir, name)
	if parent := path.Dir(final); parent != "." {
		if err := share.MkdirAll(parent, 0700); err != nil {
			return err
		}
	}
	tmp := final + ".part"
	f, err := share.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, &contextReader{ctx: ctx, r: r}); err != nil {
		_ = f.Close()
		_ = share.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = share.Remove(tmp)
		return err
	}
	// SMB rename does not replace an existing file. This leaves a small gap
	// between remove and rename; the protocol library offers no atomic replace.
	if err := share.Remove(final); err != nil && !os.IsNotExist(err) {
		_ = share.Remove(tmp)
		return err
	}
	if err := share.Rename(tmp, final); err != nil {
		_ = share.Remove(tmp)
		return err
	}
	return nil
}

func (t *smbTarget) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	name, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := budget(ctx, t.timeout)
	share, cleanup, err := t.mount(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	f, err := share.Open(path.Join(t.dir, name))
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

func (t *smbTarget) Test(ctx context.Context) error {
	ctx, cancel := budget(ctx, t.timeout)
	defer cancel()
	share, cleanup, err := t.mount(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if t.dir != "" {
		if err := share.MkdirAll(t.dir, 0700); err != nil {
			return err
		}
	}
	probe := path.Join(t.dir, pingName)
	if err := share.WriteFile(probe, []byte("ping"), 0600); err != nil {
		return err
	}
	return share.Remove(probe)
}
