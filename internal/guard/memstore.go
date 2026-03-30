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
	"context"
	"sync"
	"time"
)

// MemPendingStore is the in-process implementation of PendingStore.
// Entries are held in a map protected by a mutex.  A process restart discards
// all pending requests; use a distributed store for multi-instance deployments.
type MemPendingStore struct {
	maxEntries int // 0 = unlimited
	mu         sync.Mutex
	entries    map[string]PendingRequest
}

// NewMemPendingStore creates an in-memory PendingStore.
// maxEntries caps the number of simultaneous pending requests; 0 is unlimited.
func NewMemPendingStore(maxEntries int) *MemPendingStore {
	return &MemPendingStore{
		maxEntries: maxEntries,
		entries:    make(map[string]PendingRequest),
	}
}

func (s *MemPendingStore) StorePending(_ context.Context, req PendingRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxEntries > 0 && len(s.entries) >= s.maxEntries {
		return ErrCapacityExceeded
	}
	s.entries[req.JTI] = req
	return nil
}

func (s *MemPendingStore) GetPending(_ context.Context, jti string) (PendingRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.entries[jti]
	if !ok || time.Now().After(req.ExpiresAt) {
		return PendingRequest{}, false, nil
	}
	return req, true, nil
}

func (s *MemPendingStore) PurgeExpired(_ context.Context) error {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for jti, req := range s.entries {
		if req.ExpiresAt.Before(now) {
			delete(s.entries, jti)
		}
	}
	return nil
}

// MemUnclaimedStore is the in-process implementation of UnclaimedStore.
// Tokens are held in a nested map (userID → jti → token) protected by a
// mutex.  A process restart discards all unclaimed tokens; use a distributed
// store for multi-instance deployments.
type MemUnclaimedStore struct {
	maxPerUser int // 0 = unlimited
	maxTotal   int // 0 = unlimited
	mu         sync.Mutex
	// Outer key: UserID.  Inner key: JTI.
	entries map[string]map[string]UnclaimedToken
}

// NewMemUnclaimedStore creates an in-memory UnclaimedStore.
// maxPerUser and maxTotal are capacity limits; 0 means unlimited.
func NewMemUnclaimedStore(maxPerUser, maxTotal int) *MemUnclaimedStore {
	return &MemUnclaimedStore{
		maxPerUser: maxPerUser,
		maxTotal:   maxTotal,
		entries:    make(map[string]map[string]UnclaimedToken),
	}
}

func (s *MemUnclaimedStore) AddUnclaimed(_ context.Context, tok UnclaimedToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxPerUser > 0 && len(s.entries[tok.UserID]) >= s.maxPerUser {
		return ErrCapacityExceeded
	}
	if s.maxTotal > 0 {
		total := 0
		for _, m := range s.entries {
			total += len(m)
		}
		if total >= s.maxTotal {
			return ErrCapacityExceeded
		}
	}
	if s.entries[tok.UserID] == nil {
		s.entries[tok.UserID] = make(map[string]UnclaimedToken)
	}
	s.entries[tok.UserID][tok.JTI] = tok
	return nil
}

func (s *MemUnclaimedStore) ListUnclaimed(_ context.Context, userID string) ([]UnclaimedToken, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	userTokens := s.entries[userID]
	result := make([]UnclaimedToken, 0, len(userTokens))
	for _, tok := range userTokens {
		if !tok.ExpiresAt.Before(now) {
			result = append(result, tok)
		}
	}
	return result, nil
}

func (s *MemUnclaimedStore) ClaimToken(_ context.Context, jti string) (*UnclaimedToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for userID, userTokens := range s.entries {
		if tok, ok := userTokens[jti]; ok {
			cp := tok
			delete(userTokens, jti)
			if len(userTokens) == 0 {
				delete(s.entries, userID)
			}
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *MemUnclaimedStore) PurgeExpired(_ context.Context) error {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for userID, userTokens := range s.entries {
		for jti, tok := range userTokens {
			if tok.ExpiresAt.Before(now) {
				delete(userTokens, jti)
			}
		}
		if len(userTokens) == 0 {
			delete(s.entries, userID)
		}
	}
	return nil
}
