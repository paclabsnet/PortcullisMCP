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

package guard

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookieCryptoRoundTrip(t *testing.T) {
	crypto := NewCookieCrypto("test-secret")

	t.Run("roundtrip", func(t *testing.T) {
		plaintext := "hello-session-id-12345"
		encrypted, err := crypto.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if encrypted == plaintext {
			t.Fatal("encrypted value should differ from plaintext")
		}
		decrypted, err := crypto.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if decrypted != plaintext {
			t.Fatalf("got %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("different_nonces_each_encryption", func(t *testing.T) {
		plaintext := "same-input"
		enc1, _ := crypto.Encrypt(plaintext)
		enc2, _ := crypto.Encrypt(plaintext)
		if enc1 == enc2 {
			t.Fatal("two encryptions of the same plaintext should produce different ciphertexts")
		}
	})

	t.Run("tampered_ciphertext_rejected", func(t *testing.T) {
		enc, _ := crypto.Encrypt("value")
		// Corrupt a byte well inside the ciphertext (past the nonce).
		// Decode, flip a byte in the auth tag area, re-encode.
		raw, _ := base64.RawURLEncoding.DecodeString(enc)
		if len(raw) > 4 {
			raw[len(raw)/2] ^= 0xFF
		}
		tampered := base64.RawURLEncoding.EncodeToString(raw)
		_, err := crypto.Decrypt(tampered)
		if err == nil {
			t.Fatal("expected error for tampered ciphertext")
		}
	})

	t.Run("different_key_rejected", func(t *testing.T) {
		other := NewCookieCrypto("different-secret")
		enc, _ := crypto.Encrypt("value")
		_, err := other.Decrypt(enc)
		if err == nil {
			t.Fatal("expected error when decrypting with a different key")
		}
	})
}

func TestSetGetSessionCookie(t *testing.T) {
	crypto := NewCookieCrypto("secret")
	sessionID := "my-opaque-session-id"

	w := httptest.NewRecorder()
	if err := SetSessionCookie(w, crypto, sessionID, false); err != nil {
		t.Fatalf("SetSessionCookie: %v", err)
	}

	// Read the cookie from the response and inject into a new request.
	resp := w.Result()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}

	got, err := GetSessionCookie(req, crypto)
	if err != nil {
		t.Fatalf("GetSessionCookie: %v", err)
	}
	if got != sessionID {
		t.Fatalf("got %q, want %q", got, sessionID)
	}
}

func TestGetSessionCookieAbsent(t *testing.T) {
	crypto := NewCookieCrypto("secret")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got, err := GetSessionCookie(req, crypto)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestValidateReturnPath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"approve", "/approve", "/approve"},
		{"approve_with_query", "/approve?jti=abc", "/approve?jti=abc"},
		{"absolute_url", "https://evil.com/steal", ""},
		{"protocol_relative", "//evil.com", ""},
		{"unknown_path", "/admin", ""},
		{"auth_path", "/auth/callback", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validateReturnPath(tc.input)
			if got != tc.want {
				t.Fatalf("validateReturnPath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
