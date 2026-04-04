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
	"sync"
)

// memorySession holds the state for a single session.
type memorySession struct {
	userID string
	state  []byte
}

// MemorySessionStore is a thread-safe in-memory implementation of SessionStore.
// It is suitable for single-tenant mode and testing. It does not persist state
// across restarts and has no TTL eviction.
type MemorySessionStore struct {
	mu   sync.RWMutex
	data map[string]memorySession
}

// NewMemorySessionStore creates an empty MemorySessionStore.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{data: make(map[string]memorySession)}
}

// SaveSession stores the session state for the given sessionID.
func (s *MemorySessionStore) SaveSession(_ context.Context, sessionID, userID string, state []byte) error {
	s.mu.Lock()
	s.data[sessionID] = memorySession{userID: userID, state: state}
	s.mu.Unlock()
	return nil
}

// GetSession retrieves the session state and userID for the given sessionID.
// Returns ErrSessionNotFound if the session does not exist.
func (s *MemorySessionStore) GetSession(_ context.Context, sessionID string) ([]byte, string, error) {
	s.mu.RLock()
	sess, ok := s.data[sessionID]
	s.mu.RUnlock()
	if !ok {
		return nil, "", ErrSessionNotFound
	}
	return sess.state, sess.userID, nil
}

// DeleteSession removes the session with the given sessionID.
// It is not an error if the session does not exist.
func (s *MemorySessionStore) DeleteSession(_ context.Context, sessionID string) error {
	s.mu.Lock()
	delete(s.data, sessionID)
	s.mu.Unlock()
	return nil
}
