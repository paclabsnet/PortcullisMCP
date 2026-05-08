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

package keep

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// userToken holds an OAuth access/refresh token pair for a specific backend+user combination.
type userToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry"`
}

// pendingAuth holds the PKCE and metadata for an in-progress OAuth authorization flow.
// It is keyed by the nonce/state parameter and consumed atomically on callback.
type pendingAuth struct {
	CodeVerifier  string `json:"code_verifier"`
	BackendName   string `json:"backend_name"`
	UserID        string `json:"user_id"`
	TokenEndpoint string `json:"token_endpoint"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
}

// clientReg holds dynamic client registration credentials for a backend.
type clientReg struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64  `json:"client_secret_expires_at,omitempty"` // Unix timestamp; 0 = never expires
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	Scopes                  string `json:"scope,omitempty"`
}

// CredentialsStore manages per-user OAuth tokens, in-progress flow state, and
// dynamic client registrations across all configured backends.
// Implementations must be safe for concurrent use.
type CredentialsStore interface {
	GetToken(ctx context.Context, backend, userID string) (*userToken, error)
	SetToken(ctx context.Context, backend, userID string, token *userToken) error
	DeleteToken(ctx context.Context, backend, userID string) error
	// StorePending stores the pending OAuth flow keyed by nonce.
	// ttl controls how long the entry lives; implementations must enforce it so
	// that the replay window matches the configured flow_timeout_secs.
	// A zero or negative ttl falls back to a safe default (10 minutes).
	StorePending(ctx context.Context, nonce string, p *pendingAuth, ttl time.Duration) error
	// ConsumePending atomically returns and deletes the pending flow for nonce.
	// Returns (nil, nil) if the nonce is unknown, already consumed, or expired.
	ConsumePending(ctx context.Context, nonce string) (*pendingAuth, error)
	GetClientReg(ctx context.Context, backend string) (*clientReg, error)
	// SetClientRegNX atomically sets the client registration only if one does not already exist.
	// Returns (true, nil) if set, (false, nil) if a registration already exists.
	SetClientRegNX(ctx context.Context, backend string, reg *clientReg) (bool, error)
	// LockDCR acquires an exclusive lock for the given backend's DCR flow.
	// Returns an unlock function and nil on success. Callers must call unlock when done.
	LockDCR(ctx context.Context, backend string) (func(), error)
	// GetDCRFailure returns the cached failure reason for a recent failed DCR attempt,
	// or "" if no failure is cached (or the cache has expired).
	GetDCRFailure(ctx context.Context, backend string) (string, error)
	// SetDCRFailure records a DCR failure reason in the store for the given TTL.
	SetDCRFailure(ctx context.Context, backend string, reason string, ttl time.Duration) error
}

const defaultPendingTTL = 10 * time.Minute

// pendingEntry wraps a pendingAuth with an expiry time for the memory store.
type pendingEntry struct {
	auth   *pendingAuth
	expiry time.Time
}

// dcrFailureEntry records a cached DCR failure reason and its expiry.
type dcrFailureEntry struct {
	reason string
	expiry time.Time
}

// memoryCredentialsStore is a single-process, non-persistent CredentialsStore.
// It is safe for concurrent use but state is lost on restart.
type memoryCredentialsStore struct {
	mu          sync.RWMutex
	tokens      map[string]*userToken
	pending     map[string]*pendingEntry
	clients     map[string]*clientReg
	dcrFailures map[string]*dcrFailureEntry
	dcrLocks    map[string]*sync.Mutex
	dcrLocksMu  sync.Mutex
}

// NewMemoryCredentialsStore returns a CredentialsStore backed by in-process maps.
func NewMemoryCredentialsStore() CredentialsStore {
	return &memoryCredentialsStore{
		tokens:      make(map[string]*userToken),
		pending:     make(map[string]*pendingEntry),
		clients:     make(map[string]*clientReg),
		dcrFailures: make(map[string]*dcrFailureEntry),
		dcrLocks:    make(map[string]*sync.Mutex),
	}
}

func memTokenKey(backend, userID string) string {
	// Use a null byte as a separator that cannot appear in valid backend names or user IDs.
	return backend + "\x00" + userID
}

func (s *memoryCredentialsStore) GetToken(_ context.Context, backend, userID string) (*userToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, ok := s.tokens[memTokenKey(backend, userID)]; ok {
		return t, nil
	}
	return nil, nil
}

func (s *memoryCredentialsStore) SetToken(_ context.Context, backend, userID string, token *userToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[memTokenKey(backend, userID)] = token
	return nil
}

func (s *memoryCredentialsStore) DeleteToken(_ context.Context, backend, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, memTokenKey(backend, userID))
	return nil
}

func (s *memoryCredentialsStore) StorePending(_ context.Context, nonce string, p *pendingAuth, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = defaultPendingTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[nonce] = &pendingEntry{auth: p, expiry: time.Now().Add(ttl)}
	return nil
}

func (s *memoryCredentialsStore) ConsumePending(_ context.Context, nonce string) (*pendingAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.pending[nonce]
	if !ok {
		return nil, nil
	}
	delete(s.pending, nonce)
	if time.Now().After(entry.expiry) {
		return nil, nil // expired
	}
	return entry.auth, nil
}

func (s *memoryCredentialsStore) GetClientReg(_ context.Context, backend string) (*clientReg, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.clients[backend]; ok {
		return r, nil
	}
	return nil, nil
}

func (s *memoryCredentialsStore) SetClientRegNX(_ context.Context, backend string, reg *clientReg) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[backend]; exists {
		return false, nil
	}
	s.clients[backend] = reg
	return true, nil
}

func (s *memoryCredentialsStore) LockDCR(_ context.Context, backend string) (func(), error) {
	s.dcrLocksMu.Lock()
	mu, ok := s.dcrLocks[backend]
	if !ok {
		mu = &sync.Mutex{}
		s.dcrLocks[backend] = mu
	}
	s.dcrLocksMu.Unlock()

	mu.Lock()
	return func() { mu.Unlock() }, nil
}

func (s *memoryCredentialsStore) GetDCRFailure(_ context.Context, backend string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.dcrFailures[backend]
	if !ok {
		return "", nil
	}
	if time.Now().After(entry.expiry) {
		return "", nil // expired
	}
	return entry.reason, nil
}

func (s *memoryCredentialsStore) SetDCRFailure(_ context.Context, backend string, reason string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("dcr failure ttl must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dcrFailures[backend] = &dcrFailureEntry{reason: reason, expiry: time.Now().Add(ttl)}
	return nil
}

