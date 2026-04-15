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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

const (
	cookieSession    = "portcullis_session"
	cookieLoginState = "portcullis_login_state"
)

// CookieCrypto handles AES-256-GCM encryption and decryption for session cookies.
// The key is derived from a secret string using SHA-256.
type CookieCrypto struct {
	key [32]byte
}

// NewCookieCrypto creates a CookieCrypto using the SHA-256 hash of secret as the AES-256 key.
func NewCookieCrypto(secret string) *CookieCrypto {
	return &CookieCrypto{key: sha256.Sum256([]byte(secret))}
}

// Encrypt encrypts plaintext using AES-256-GCM and returns a base64url-encoded ciphertext.
func (c *CookieCrypto) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(c.key[:])
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64url-encoded AES-256-GCM ciphertext produced by Encrypt.
func (c *CookieCrypto) Decrypt(encoded string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode cookie: %w", err)
	}

	block, err := aes.NewCipher(c.key[:])
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt cookie: %w", err)
	}
	return string(plaintext), nil
}

// SetSessionCookie writes the encrypted portcullis_session cookie to the response.
// It is long-lived (expires with the session — we rely on server-side TTL).
func SetSessionCookie(w http.ResponseWriter, crypto *CookieCrypto, sessionID string, secure bool) error {
	value, err := crypto.Encrypt(sessionID)
	if err != nil {
		return fmt.Errorf("encrypt session cookie: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieSession,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// GetSessionCookie reads and decrypts the portcullis_session cookie.
// Returns ("", nil) if the cookie is absent.
func GetSessionCookie(r *http.Request, crypto *CookieCrypto) (string, error) {
	cookie, err := r.Cookie(cookieSession)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", nil
		}
		return "", err
	}
	sessionID, err := crypto.Decrypt(cookie.Value)
	if err != nil {
		return "", fmt.Errorf("invalid session cookie: %w", err)
	}
	return sessionID, nil
}

// ClearSessionCookie expires the portcullis_session cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieSession,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

// SetLoginStateCookie writes the encrypted portcullis_login_state correlation cookie.
// TTL is fixed at 10 minutes to match the PKCE state expiry.
func SetLoginStateCookie(w http.ResponseWriter, crypto *CookieCrypto, stateID string, secure bool) error {
	value, err := crypto.Encrypt(stateID)
	if err != nil {
		return fmt.Errorf("encrypt login state cookie: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieLoginState,
		Value:    value,
		Path:     "/auth/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(pkceStateExpiry.Seconds()),
	})
	return nil
}

// GetLoginStateCookie reads and decrypts the portcullis_login_state cookie.
// Returns ("", nil) if absent.
func GetLoginStateCookie(r *http.Request, crypto *CookieCrypto) (string, error) {
	cookie, err := r.Cookie(cookieLoginState)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", nil
		}
		return "", err
	}
	stateID, err := crypto.Decrypt(cookie.Value)
	if err != nil {
		return "", fmt.Errorf("invalid login state cookie: %w", err)
	}
	return stateID, nil
}

// ClearLoginStateCookie expires the portcullis_login_state cookie.
func ClearLoginStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieLoginState,
		Value:    "",
		Path:     "/auth/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

// NewSessionID generates a new cryptographically random opaque session ID.
func NewSessionID() string {
	return uuid.New().String()
}
