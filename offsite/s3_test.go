package offsite

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestS3PutGetAndMissing(t *testing.T) {
	objects := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" || r.Header.Get("x-amz-date") == "" || r.Header.Get("x-amz-content-sha256") == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPut:
			raw, _ := io.ReadAll(r.Body)
			objects[r.URL.Path] = string(raw)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			if r.Header.Get("x-amz-content-sha256") != "UNSIGNED-PAYLOAD" {
				http.Error(w, "GET payload was not unsigned", http.StatusUnauthorized)
				return
			}
			value, ok := objects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, value)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	target, err := Parse(Config{URL: "s3://bucket/prefix", S3Endpoint: server.URL, S3Region: "auto", AccessKey: "key", Secret: "secret", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s3 := target.(*s3Target)
	s3.now = func() time.Time { return time.Date(2026, 9, 5, 1, 2, 3, 0, time.UTC) }
	if err := target.Put(context.Background(), "folder/object", strings.NewReader("payload"), 7); err != nil {
		t.Fatal(err)
	}
	r, err := target.Get(context.Background(), "folder/object")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || string(raw) != "payload" {
		t.Fatalf("Get = %q, %v", raw, err)
	}
	if _, err := target.Get(context.Background(), "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing error = %v", err)
	}
	if err := target.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if objects["/bucket/prefix/"+pingName] != "ping" {
		t.Fatalf("probe objects = %#v", objects)
	}
}

func TestS3UsesVirtualHostedAWSURL(t *testing.T) {
	target, err := Parse(Config{URL: "s3://my-bucket/a b", AccessKey: "key", Secret: "secret", S3Region: "us-west-2"})
	if err != nil {
		t.Fatal(err)
	}
	u := target.(*s3Target).objectURL("object")
	if got, want := u.String(), "https://my-bucket.s3.us-west-2.amazonaws.com/a%20b/object"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

func TestS3ErrorBodyIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, strings.Repeat("x", 20000))
	}))
	defer server.Close()
	target, err := Parse(Config{URL: "s3://bucket", S3Endpoint: server.URL, AccessKey: "key", Secret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	err = target.Put(context.Background(), "object", strings.NewReader("x"), 1)
	if err == nil || len(err.Error()) > 8300 {
		t.Fatalf("error length = %d", len(err.Error()))
	}
}

func TestS3RefusesRedirect(t *testing.T) {
	followed := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed = true
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	target, err := Parse(Config{URL: "s3://bucket", S3Endpoint: redirect.URL, AccessKey: "key", Secret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Put(context.Background(), "object", strings.NewReader("x"), 1); err == nil {
		t.Fatal("redirect was accepted")
	}
	if followed {
		t.Fatal("S3 request followed a redirect and exposed its authorization header")
	}
}
