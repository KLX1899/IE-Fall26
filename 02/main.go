package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const issuer = "http-hands-on-proxy"
const audience = "httpbin"

type claims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
	Expires   int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
}

func main() {
	key := []byte(os.Getenv("JWT_SECRET"))
	if len(key) < 32 {
		log.Fatal("JWT_SECRET must contain at least 32 bytes")
	}

	if len(os.Args) > 1 {
		if len(os.Args) != 3 || os.Args[1] != "mint" || strings.TrimSpace(os.Args[2]) == "" {
			log.Fatal("usage: proxy mint SUBJECT")
		}
		token, err := mint(os.Args[2], key, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(token)
		return
	}

	target, err := url.Parse(os.Getenv("UPSTREAM_URL"))
	if err != nil || target == nil || target.Scheme != "http" || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		log.Fatal("UPSTREAM_URL must be an HTTP origin, for example http://httpbin:8081")
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{Addr: addr, Handler: newProxy(target, key), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

func newProxy(target *url.URL, key []byte) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.Out.Host = request.In.Host
			request.SetXForwarded()
			request.Out.Header.Del("Authorization")
			request.Out.Header.Del("Proxy-Authorization")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Values("Authorization")
		if len(authorization) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "valid bearer token required", http.StatusUnauthorized)
			return
		}
		parts := strings.Fields(authorization[0])
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !validToken(parts[1], key, time.Now()) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "valid bearer token required", http.StatusUnauthorized)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

func validToken(token string, key []byte, now time.Time) bool {
	if len(token) > 8192 {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var metadata struct {
		Algorithm string `json:"alg"`
	}
	if json.Unmarshal(header, &metadata) != nil || metadata.Algorithm != "HS256" {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var c claims
	if json.Unmarshal(payload, &c) != nil {
		return false
	}
	return c.Issuer == issuer && c.Audience == audience && c.Subject != "" && c.Expires > now.Unix() && c.NotBefore <= now.Unix()
}

func mint(subject string, key []byte, now time.Time) (string, error) {
	return sign(claims{issuer, audience, subject, now.Add(time.Hour).Unix(), now.Unix()}, key)
}

func sign(c claims, key []byte) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
