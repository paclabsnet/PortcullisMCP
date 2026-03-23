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

// TokenStore manages the local escalation token file.
// The file is owned and readable only by the current user (mode 0600).
type TokenStore struct {
	mu   sync.RWMutex
	path string
	// tokens is the in-memory copy, pruned of expired entries.
	tokens []shared.EscalationToken
}

// NewTokenStore opens (or creates) the token store at the given path,
// loads existing tokens, and prunes expired ones.
func NewTokenStore(_ context.Context, path string) (*TokenStore, error) {
	expanded, err := expandHome(path)
	if err != nil {
		return nil, fmt.Errorf("expand token store path: %w", err)
	}
	ts := &TokenStore{path: expanded}
	if err := ts.load(); err != nil {
		return nil, err
	}
	return ts, nil
}

// All returns a snapshot of all currently valid (non-expired) tokens.
func (ts *TokenStore) All() []shared.EscalationToken {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make([]shared.EscalationToken, len(ts.tokens))
	copy(out, ts.tokens)
	return out
}

// Add validates and persists a new token. If the token is already expired it
// is rejected. Duplicate TokenIDs are replaced.
func (ts *TokenStore) Add(_ context.Context, raw string) (shared.EscalationToken, error) {
	tok, err := parseEscalationToken(raw)
	if err != nil {
		return shared.EscalationToken{}, fmt.Errorf("parse token: %w", err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Replace duplicate.
	replaced := false
	for i, t := range ts.tokens {
		if t.TokenID == tok.TokenID {
			ts.tokens[i] = tok
			replaced = true
			break
		}
	}
	if !replaced {
		ts.tokens = append(ts.tokens, tok)
	}
	return tok, ts.saveLocked()
}

// Delete removes the token with the given ID and persists the change.
func (ts *TokenStore) Delete(_ context.Context, tokenID string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	n := len(ts.tokens)
	filtered := ts.tokens[:0]
	for _, t := range ts.tokens {
		if t.TokenID != tokenID {
			filtered = append(filtered, t)
		}
	}
	ts.tokens = filtered
	if len(ts.tokens) == n {
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

	var raws []string
	if err := json.Unmarshal(data, &raws); err != nil {
		return fmt.Errorf("parse token store: %w", err)
	}

	for _, raw := range raws {
		tok, err := parseEscalationToken(raw)
		if err != nil {
			// Skip malformed tokens silently.
			continue
		}
		ts.tokens = append(ts.tokens, tok)
	}
	return nil
}

// saveLocked writes the current token list to disk. Caller must hold ts.mu.
func (ts *TokenStore) saveLocked() error {
	raws := make([]string, len(ts.tokens))
	for i, t := range ts.tokens {
		raws[i] = t.Raw
	}
	data, err := json.MarshalIndent(raws, "", "  ")
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
