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

// Package oidcutil provides low-level OIDC/PKCE helpers shared by Gate and Guard.
// These are purely cryptographic or encoding utilities; all login-lifecycle logic
// (discovery, token exchange, session management) stays in each service's own package.
package oidcutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// GenerateRandomString returns a URL-safe base64-encoded random string of n bytes.
func GenerateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// PKCEChallenge computes the S256 PKCE code challenge from a verifier.
func PKCEChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// UnsafeParseJWTClaims decodes the payload of a JWT without verifying the
// signature. Used only to extract display claims (sub, name, nonce, exp, etc.);
// the PDP must perform authoritative signature verification.
func UnsafeParseJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: expected 3 parts, got %d", len(parts))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode jwt payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal jwt claims: %w", err)
	}
	return claims, nil
}
