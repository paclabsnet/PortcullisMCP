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
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// CredentialsStore manages per-user OAuth tokens, in-progress flow state, and
// dynamic client registrations across all configured backends.
// Implementations must be safe for concurrent use.
type CredentialsStore interface {
	GetToken(ctx context.Context, backend, userID string) (*userToken, error)
	SetToken(ctx context.Context, backend, userID string, token *userToken) error
	DeleteToken(ctx context.Context, backend, userID string) error
	StorePending(ctx context.Context, nonce string, p *pendingAuth) error
	// ConsumePending atomically returns and deletes the pending flow for nonce.
	// Returns (nil, nil) if the nonce is unknown or already consumed.
	ConsumePending(ctx context.Context, nonce string) (*pendingAuth, error)
	GetClientReg(ctx context.Context, backend string) (*clientReg, error)
	SetClientReg(ctx context.Context, backend string, reg *clientReg) error
}

// memoryCredentialsStore is a single-process, non-persistent CredentialsStore.
// It is safe for concurrent use but state is lost on restart.
type memoryCredentialsStore struct {
	mu      sync.RWMutex
	tokens  map[string]*userToken
	pending map[string]*pendingAuth
	clients map[string]*clientReg
}

// NewMemoryCredentialsStore returns a CredentialsStore backed by in-process maps.
func NewMemoryCredentialsStore() CredentialsStore {
	return &memoryCredentialsStore{
		tokens:  make(map[string]*userToken),
		pending: make(map[string]*pendingAuth),
		clients: make(map[string]*clientReg),
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

func (s *memoryCredentialsStore) StorePending(_ context.Context, nonce string, p *pendingAuth) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[nonce] = p
	return nil
}

func (s *memoryCredentialsStore) ConsumePending(_ context.Context, nonce string) (*pendingAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[nonce]
	if !ok {
		return nil, nil
	}
	delete(s.pending, nonce)
	return p, nil
}

func (s *memoryCredentialsStore) GetClientReg(_ context.Context, backend string) (*clientReg, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.clients[backend]; ok {
		return r, nil
	}
	return nil, nil
}

func (s *memoryCredentialsStore) SetClientReg(_ context.Context, backend string, reg *clientReg) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[backend] = reg
	return nil
}
