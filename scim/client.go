package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// maxBody is the most of any response the client reads. A User is a few kilobytes.
const maxBody = 1 << 20

// Client talks to one SCIM server. The zero HTTPClient is a ten-second client; products with
// an outbound policy (private-range refusal, dial guards) pass their own. Redirects are
// refused whatever client is passed.
type Client struct {
	// BaseURL is the SCIM root, e.g. https://host/scim/v2. HTTPS only.
	BaseURL string
	// Token is sent as Authorization: Bearer and nowhere else.
	Token      string
	HTTPClient *http.Client
}

// Ping fetches ServiceProviderConfig, which proves the URL is a SCIM root and the token is
// accepted without touching a user.
func (c *Client) Ping(ctx context.Context) error {
	u, err := c.endpoint("", "ServiceProviderConfig")
	if err != nil {
		return err
	}
	var probe struct{}
	return c.do(ctx, http.MethodGet, u, nil, &probe)
}

// CreateUser POSTs the user and returns the resource the server minted. The returned ID is
// the handle for every later call; the caller's ID and Meta are not sent. A 409 is
// ErrConflict, never success.
func (c *Client) CreateUser(ctx context.Context, user User) (User, error) {
	u, err := c.endpoint("", "Users")
	if err != nil {
		return User{}, err
	}
	var out User
	if err := c.do(ctx, http.MethodPost, u, outbound(user), &out); err != nil {
		return User{}, err
	}
	if out.ID == "" {
		return User{}, fmt.Errorf("%w: create returned no id", ErrMalformedResponse)
	}
	return out, nil
}

// GetUser fetches one user by the server's ID.
func (c *Client) GetUser(ctx context.Context, id string) (User, error) {
	u, err := c.user(id)
	if err != nil {
		return User{}, err
	}
	var out User
	return out, c.do(ctx, http.MethodGet, u, nil, &out)
}

var attributePath = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]*$`)

// FindUser looks a user up by an equality filter on one attribute, "externalId" or
// "userName" in practice. Zero matches is ErrNotFound; more than one is ErrAmbiguous, since a
// caller that took the first would act on the wrong account.
func (c *Client) FindUser(ctx context.Context, attribute, value string) (User, error) {
	if !attributePath.MatchString(attribute) {
		return User{}, fmt.Errorf("scim: filter attribute %q is not a plain attribute path", attribute)
	}
	quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
	u, err := c.endpoint(attribute+` eq "`+quoted+`"`, "Users")
	if err != nil {
		return User{}, err
	}
	var list struct {
		TotalResults int    `json:"totalResults"`
		Resources    []User `json:"Resources"`
	}
	if err := c.do(ctx, http.MethodGet, u, nil, &list); err != nil {
		return User{}, err
	}
	switch {
	case len(list.Resources) == 0:
		return User{}, ErrNotFound
	case len(list.Resources) > 1 || list.TotalResults > 1:
		return User{}, ErrAmbiguous
	}
	return list.Resources[0], nil
}

// ReplaceUser PUTs the whole user under the server's ID.
func (c *Client) ReplaceUser(ctx context.Context, id string, user User) (User, error) {
	u, err := c.user(id)
	if err != nil {
		return User{}, err
	}
	var out User
	return out, c.do(ctx, http.MethodPut, u, outbound(user), &out)
}

// PatchUser applies operations, e.g. {Op: "replace", Path: "active", Value: false} to
// deprovision. The returned User is zero when the server answers 204.
func (c *Client) PatchUser(ctx context.Context, id string, ops ...PatchOperation) (User, error) {
	if len(ops) == 0 {
		return User{}, fmt.Errorf("scim: patch needs at least one operation")
	}
	u, err := c.user(id)
	if err != nil {
		return User{}, err
	}
	body := struct {
		Schemas    []string         `json:"schemas"`
		Operations []PatchOperation `json:"Operations"`
	}{[]string{PatchOpSchema}, ops}
	var out User
	return out, c.do(ctx, http.MethodPatch, u, body, &out)
}

// DeleteUser removes the user. A 404 is ErrNotFound; whether that is fine is the caller's call.
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	u, err := c.user(id)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, u, nil, nil)
}

// outbound is the user as sent: schema filled in, server-owned fields cleared.
func outbound(user User) User {
	user.ID, user.Meta = "", nil
	if len(user.Schemas) == 0 {
		user.Schemas = []string{UserSchema}
	}
	return user
}

// user is the URL of one user. The ID is path-escaped and must be a real segment: an empty
// one turns DELETE /Users/{id} into DELETE /Users, and a dot would be cleaned out of the path.
func (c *Client) user(id string) (string, error) {
	if id == "" || id == "." || id == ".." {
		return "", fmt.Errorf("scim: %q is not a resource id", id)
	}
	return c.endpoint("", "Users", url.PathEscape(id))
}

// endpoint validates BaseURL and joins the escaped segments and optional filter onto it.
func (c *Client) endpoint(filter string, segments ...string) (string, error) {
	base, err := url.Parse(c.BaseURL)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil ||
		base.RawQuery != "" || base.ForceQuery || base.Fragment != "" {
		return "", ErrInsecureURL
	}
	if c.Token == "" {
		return "", ErrNoToken
	}
	u := base.JoinPath(segments...)
	if filter != "" {
		u.RawQuery = url.Values{"filter": {filter}}.Encode()
	}
	return u.String(), nil
}

func (c *Client) do(ctx context.Context, method, target string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("Accept", "application/scim+json, application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)

	base := c.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: 10 * time.Second}
	}
	// Go would replay the body, and the bearer, wherever the server pointed.
	client := *base
	client.CheckRedirect = func(r *http.Request, _ []*http.Request) error {
		return fmt.Errorf("scim: server redirected to %s; redirects are refused", r.URL.Redacted())
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	if resp.StatusCode >= 400 {
		return remoteError(resp, raw)
	}
	if len(raw) > maxBody {
		return fmt.Errorf("%w: body exceeds %d bytes", ErrMalformedResponse, maxBody)
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	return nil
}

// remoteError reads the RFC 7644 error body when there is one. The status comes from the
// response line, not the body, so a body that lies or is not JSON still classifies.
func remoteError(resp *http.Response, raw []byte) error {
	e := &Error{Status: resp.StatusCode, RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	var body struct {
		ScimType string `json:"scimType"`
		Detail   string `json:"detail"`
	}
	if json.Unmarshal(raw, &body) == nil {
		e.ScimType, e.Detail = printable(body.ScimType), printable(body.Detail)
	}
	return e
}

func retryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
