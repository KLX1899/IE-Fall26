package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyRequiresJWTAndForwardsRequest(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	var forwarded atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" {
			http.Error(w, "credentials leaked", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.RequestURI() != "/anything?x=1" || string(body) != "hello" {
			http.Error(w, "request changed", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	proxy := httptest.NewServer(newProxy(target, key))
	defer proxy.Close()

	now := time.Now()
	valid, err := mint("alice", key, now)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := sign(claims{issuer, audience, "alice", now.Add(-time.Minute).Unix(), now.Add(-time.Hour).Unix()}, key)
	if err != nil {
		t.Fatal(err)
	}
	future, err := sign(claims{issuer, audience, "alice", now.Add(time.Hour).Unix(), now.Add(time.Minute).Unix()}, key)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		token      string
		wantStatus int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"tampered", valid + "x", http.StatusUnauthorized},
		{"expired", expired, http.StatusUnauthorized},
		{"not yet valid", future, http.StatusUnauthorized},
		{"valid", valid, http.StatusCreated},
	} {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, proxy.URL+"/anything?x=1", strings.NewReader("hello"))
			if err != nil {
				t.Fatal(err)
			}
			if test.token != "" {
				req.Header.Set("Authorization", "Bearer "+test.token)
				req.Header.Set("Proxy-Authorization", "secret")
			}
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.wantStatus)
			}
		})
	}
	if forwarded.Load() != 1 {
		t.Fatalf("backend received %d requests, want 1", forwarded.Load())
	}
}
