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

// MemStore is the in-process implementation of both PendingStore and UnclaimedStore.
type MemStore struct {
	maxPending int
	maxTotal   int
	maxPerUser int

	mu             sync.Mutex
	pendingEntries map[string]PendingRequest
	// Outer key: UserID.  Inner key: JTI.
	unclaimedEntries map[string]map[string]UnclaimedToken
}

// NewMemStore creates an in-memory store for both pending and unclaimed entries.
func NewMemStore(maxPending, maxTotal, maxPerUser int) *MemStore {
	return &MemStore{
		maxPending:       maxPending,
		maxTotal:         maxTotal,
		maxPerUser:       maxPerUser,
		pendingEntries:   make(map[string]PendingRequest),
		unclaimedEntries: make(map[string]map[string]UnclaimedToken),
	}
}

func (s *MemStore) StorePending(_ context.Context, req PendingRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxPending > 0 && len(s.pendingEntries) >= s.maxPending {
		return ErrCapacityExceeded
	}
	s.pendingEntries[req.JTI] = req
	return nil
}

func (s *MemStore) GetPending(_ context.Context, jti string) (PendingRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.pendingEntries[jti]
	if !ok || time.Now().After(req.ExpiresAt) {
		return PendingRequest{}, false, nil
	}
	return req, true, nil
}

func (s *MemStore) AddUnclaimed(_ context.Context, tok UnclaimedToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxPerUser > 0 && len(s.unclaimedEntries[tok.UserID]) >= s.maxPerUser {
		return ErrCapacityExceeded
	}
	if s.maxTotal > 0 {
		total := 0
		for _, m := range s.unclaimedEntries {
			total += len(m)
		}
		if total >= s.maxTotal {
			return ErrCapacityExceeded
		}
	}
	if s.unclaimedEntries[tok.UserID] == nil {
		s.unclaimedEntries[tok.UserID] = make(map[string]UnclaimedToken)
	}
	s.unclaimedEntries[tok.UserID][tok.JTI] = tok
	return nil
}

func (s *MemStore) ListUnclaimed(_ context.Context, userID string) ([]UnclaimedToken, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	userTokens := s.unclaimedEntries[userID]
	result := make([]UnclaimedToken, 0, len(userTokens))
	for _, tok := range userTokens {
		if !tok.ExpiresAt.Before(now) {
			result = append(result, tok)
		}
	}
	return result, nil
}

func (s *MemStore) ClaimToken(_ context.Context, jti string) (*UnclaimedToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for userID, userTokens := range s.unclaimedEntries {
		if tok, ok := userTokens[jti]; ok {
			cp := tok
			delete(userTokens, jti)
			if len(userTokens) == 0 {
				delete(s.unclaimedEntries, userID)
			}
			return &cp, nil
		}
	}
	return nil, nil
}

func (s *MemStore) PurgeExpired(_ context.Context) error {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	// Purge pending
	for jti, req := range s.pendingEntries {
		if req.ExpiresAt.Before(now) {
			delete(s.pendingEntries, jti)
		}
	}

	// Purge unclaimed
	for userID, userTokens := range s.unclaimedEntries {
		for jti, tok := range userTokens {
			if tok.ExpiresAt.Before(now) {
				delete(userTokens, jti)
			}
		}
		if len(userTokens) == 0 {
			delete(s.unclaimedEntries, userID)
		}
	}
	return nil
}
