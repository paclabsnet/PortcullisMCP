// Copyright 2026 Policy-as-Code Laboratories (PAC.Labs)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package middleware provides shared HTTP middleware for Portcullis services.
package middleware

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
)

// AuthConfig holds the parameters for BearerAuth.
type AuthConfig struct {
	// BearerToken is the raw token value expected in the Authorization header
	// (without the "Bearer " prefix).  Empty disables Bearer verification.
	BearerToken string

	// ClientCA, when non-empty, indicates that mTLS is configured for the
	// endpoint.  A request that carries at least one peer certificate is
	// accepted without a Bearer token — mutual TLS has already authenticated
	// the caller at the transport layer.
	ClientCA string

	// SkipPaths is an optional list of URL paths that bypass all authentication
	// checks (e.g. health probes or OAuth callback endpoints).
	SkipPaths []string

	// Realm is placed in the WWW-Authenticate response header.
	// Defaults to "portcullis" when empty.
	Realm string
}

// BearerAuth returns an HTTP middleware that enforces authentication according
// to cfg.  The check order is:
//
//  1. SkipPaths — if the request path matches, the request is forwarded
//     unconditionally.
//  2. mTLS — if ClientCA is set and the request carries peer certificates, the
//     request is forwarded (TLS handshake already authenticated the caller).
//  3. Bearer token — constant-time comparison against the configured token.
//
// When all checks fail the middleware writes HTTP 401 with a JSON error body
// and a WWW-Authenticate header.  Fail-closed: if neither mTLS nor a Bearer
// token is configured, every non-skip-path request is rejected.
func BearerAuth(cfg AuthConfig) func(http.Handler) http.Handler {
	realm := cfg.Realm
	if realm == "" {
		realm = "portcullis"
	}
	// Pre-build the expected header value once to avoid allocation per request.
	expected := []byte("Bearer " + cfg.BearerToken)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Skip-list — health probes, OAuth callbacks, etc.
			for _, p := range cfg.SkipPaths {
				if r.URL.Path == p {
					next.ServeHTTP(w, r)
					return
				}
			}

			// 2. mTLS — if the endpoint has a ClientCA and the request carried
			// peer certificates through the TLS handshake, the caller is already
			// authenticated at the transport layer.
			if cfg.ClientCA != "" && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				next.ServeHTTP(w, r)
				return
			}

			// 3. Bearer token — constant-time to prevent timing side-channels.
			if cfg.BearerToken != "" {
				got := []byte(r.Header.Get("Authorization"))
				if subtle.ConstantTimeCompare(got, expected) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}

			w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid or missing bearer token"})
		})
	}
}
