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

package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// resolveStoragePrefix returns a context-derived storage key prefix for
// partitioning escalation state by caller identity. The prefix prevents
// cross-session or cross-user state leakage in shared stores (e.g. Redis).
//
// scope "session"     → "sess:{sessionID}" from context
// scope "fingerprint" → "fp:{credentialFingerprint}" from context,
//
//	falling back to "fp:{userID}" from identity source
//
// Any other scope (including "") returns "" (bare key, no partitioning).
func resolveStoragePrefix(ctx context.Context, scope string, identity IdentitySource) string {
	switch scope {
	case "session":
		if sid, ok := SessionIDFromContext(ctx); ok && sid != "" {
			return "sess:" + sid
		}
	case "fingerprint":
		if fp, ok := CredentialFingerprintFromContext(ctx); ok && fp != "" {
			return "fp:" + fp
		}
		if identity != nil {
			if uid := identity.Get(ctx).UserID; uid != "" {
				return "fp:" + uid
			}
		}
	}
	return ""
}

// EscalationTokenStore manages short-lived escalation JWTs.
type EscalationTokenStore interface {
	All(ctx context.Context) []shared.EscalationToken
	Add(ctx context.Context, raw string) (shared.EscalationToken, error)
	Delete(ctx context.Context, tokenID string) error
}

// PendingEscalationStore manages in-flight (not-yet-approved) escalation requests.
type PendingEscalationStore interface {
	Store(ctx context.Context, key string, p pendingEscalation)
	Get(ctx context.Context, key string) (pendingEscalation, bool)
	Delete(ctx context.Context, key string)
}

// InMemoryPendingStore is a thread-safe in-memory PendingEscalationStore.
type InMemoryPendingStore struct {
	mu   sync.Mutex
	data map[string]pendingEscalation
}

// NewInMemoryPendingStore creates an empty InMemoryPendingStore.
func NewInMemoryPendingStore() *InMemoryPendingStore {
	return &InMemoryPendingStore{data: make(map[string]pendingEscalation)}
}

func (s *InMemoryPendingStore) Store(_ context.Context, key string, p pendingEscalation) {
	s.mu.Lock()
	s.data[key] = p
	s.mu.Unlock()
}

func (s *InMemoryPendingStore) Get(_ context.Context, key string) (pendingEscalation, bool) {
	s.mu.Lock()
	p, ok := s.data[key]
	s.mu.Unlock()
	return p, ok
}

func (s *InMemoryPendingStore) Delete(_ context.Context, key string) {
	s.mu.Lock()
	delete(s.data, key)
	s.mu.Unlock()
}


// InMemoryTokenStore is a trivial EscalationTokenStore backed by a slice.
// It is used in multi-tenant mode when escalation is disabled (no Redis needed).
type InMemoryTokenStore struct {
	mu     sync.Mutex
	tokens []shared.EscalationToken
}

// NewInMemoryTokenStore creates an empty InMemoryTokenStore.
func NewInMemoryTokenStore() *InMemoryTokenStore { return &InMemoryTokenStore{} }

func (s *InMemoryTokenStore) All(_ context.Context) []shared.EscalationToken {
	s.mu.Lock()
	out := make([]shared.EscalationToken, len(s.tokens))
	copy(out, s.tokens)
	s.mu.Unlock()
	return out
}

func (s *InMemoryTokenStore) Add(_ context.Context, raw string) (shared.EscalationToken, error) {
	tok, err := parseEscalationToken(raw)
	if err != nil {
		return shared.EscalationToken{}, err
	}
	s.mu.Lock()
	s.tokens = append(s.tokens, tok)
	s.mu.Unlock()
	return tok, nil
}

func (s *InMemoryTokenStore) Delete(_ context.Context, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.tokens {
		if t.TokenID == tokenID {
			s.tokens = append(s.tokens[:i], s.tokens[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("token %q not found", tokenID)
}

// storedTokenEntry is the on-disk representation of an escalation token.
// ScopeKey is the resolved storage prefix at the time of Add (e.g.
// "sess:0" or "fp:abc123"). An empty ScopeKey means the entry was stored
// without a scope and is visible to all callers.
type storedTokenEntry struct {
	Raw      string `json:"raw"`
	ScopeKey string `json:"scope_key,omitempty"`
	tok      shared.EscalationToken
}

// TokenStore manages the local escalation token file.
// The file is owned and readable only by the current user (mode 0600).
// When scope and identity are set, All and Add are partitioned by the
// resolved storage prefix so that tokens from one login session are not
// visible after the credential changes (e.g. in fingerprint mode).
type TokenStore struct {
	mu       sync.RWMutex
	path     string
	scope    string
	identity IdentitySource
	// entries is the in-memory copy, pruned of expired entries.
	entries []storedTokenEntry
}

// NewTokenStore opens (or creates) the token store at the given path,
// loads existing tokens, and prunes expired ones.
// scope and identity drive per-caller partitioning (see resolveStoragePrefix).
func NewTokenStore(_ context.Context, path, scope string, identity IdentitySource) (*TokenStore, error) {
	expanded, err := expandHome(path)
	if err != nil {
		return nil, fmt.Errorf("expand token store path: %w", err)
	}
	ts := &TokenStore{path: expanded, scope: scope, identity: identity}
	if err := ts.load(); err != nil {
		return nil, err
	}
	return ts, nil
}

// All returns a snapshot of valid tokens visible to the current caller.
// If a scope prefix is resolved from ctx, only tokens tagged with that prefix
// are returned. If no prefix can be resolved (e.g. no fingerprint in context),
// all tokens are returned — this covers admin/management-console access.
func (ts *TokenStore) All(ctx context.Context) []shared.EscalationToken {
	prefix := resolveStoragePrefix(ctx, ts.scope, ts.identity)
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make([]shared.EscalationToken, 0, len(ts.entries))
	for _, e := range ts.entries {
		if prefix == "" || e.ScopeKey == prefix {
			out = append(out, e.tok)
		}
	}
	return out
}

// Add validates and persists a new token tagged with the current caller's
// scope key. If the token is already expired it is rejected. Duplicate
// TokenIDs are replaced (regardless of scope key).
func (ts *TokenStore) Add(ctx context.Context, raw string) (shared.EscalationToken, error) {
	tok, err := parseEscalationToken(raw)
	if err != nil {
		return shared.EscalationToken{}, fmt.Errorf("parse token: %w", err)
	}
	scopeKey := resolveStoragePrefix(ctx, ts.scope, ts.identity)
	entry := storedTokenEntry{Raw: raw, ScopeKey: scopeKey, tok: tok}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Replace duplicate by TokenID.
	replaced := false
	for i, e := range ts.entries {
		if e.tok.TokenID == tok.TokenID {
			ts.entries[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		ts.entries = append(ts.entries, entry)
	}
	return tok, ts.saveLocked()
}

// Delete removes the token with the given ID and persists the change.
// Deletion is not scope-filtered — it is an administrative operation.
func (ts *TokenStore) Delete(_ context.Context, tokenID string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	n := len(ts.entries)
	filtered := ts.entries[:0]
	for _, e := range ts.entries {
		if e.tok.TokenID != tokenID {
			filtered = append(filtered, e)
		}
	}
	ts.entries = filtered
	if len(ts.entries) == n {
		return fmt.Errorf("token %q not found", tokenID)
	}
	return ts.saveLocked()
}

// load reads the token file and prunes expired tokens.
// If the file does not exist the store starts empty.
func (ts *TokenStore) load() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	data, err := os.ReadFile(ts.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read token store: %w", err)
	}

	var disk []storedTokenEntry
	if err := json.Unmarshal(data, &disk); err != nil {
		return fmt.Errorf("parse token store: %w", err)
	}

	for _, e := range disk {
		tok, err := parseEscalationToken(e.Raw)
		if err != nil {
			// Skip malformed or expired tokens silently.
			continue
		}
		ts.entries = append(ts.entries, storedTokenEntry{Raw: e.Raw, ScopeKey: e.ScopeKey, tok: tok})
	}
	return nil
}

// saveLocked writes the current entry list to disk. Caller must hold ts.mu.
func (ts *TokenStore) saveLocked() error {
	data, err := json.MarshalIndent(ts.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token store: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(ts.path), 0700); err != nil {
		return fmt.Errorf("create token store dir: %w", err)
	}
	// Write with user-only permissions.
	if err := os.WriteFile(ts.path, data, 0600); err != nil {
		return fmt.Errorf("write token store: %w", err)
	}
	return nil
}

// parseEscalationToken extracts metadata from a raw JWT for storage.
// It does NOT verify the signature — the PDP does that.
func parseEscalationToken(raw string) (shared.EscalationToken, error) {
	raw = strings.TrimSpace(raw)
	claims, err := unsafeParseJWTClaims(raw)
	if err != nil {
		return shared.EscalationToken{}, err
	}

	// Reject already-expired tokens.
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return shared.EscalationToken{}, fmt.Errorf("token is expired")
		}
	}

	tok := shared.EscalationToken{Raw: raw}
	if v, ok := claims["jti"].(string); ok {
		tok.TokenID = v
	} else if v, ok := claims["sub"].(string); ok {
		tok.TokenID = v
	}
	if tok.TokenID == "" {
		return shared.EscalationToken{}, fmt.Errorf("token missing jti/sub claim")
	}
	if v, ok := claims["granted_by"].(string); ok {
		tok.GrantedBy = v
	}
	return tok, nil
}

// expandHome replaces a leading "~" with the current user's home directory.
func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, path[1:]), nil
}
