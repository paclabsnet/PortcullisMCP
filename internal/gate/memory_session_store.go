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
	"time"
)

/*
 *  In production instances, we would expect that the IT admins
 *  would use redis as a backend (or something similar).  But
 *  for experimentation and PoC development, we want to avoid
 *  adding requirements. You could conceivably run a multi-tenant
 *  Gate in a cluster with sticky sessions using this, but we
 *  don't recommend it.
 */

const (
	// defaultMemorySessionMaxEntries bounds the store so unauthenticated
	// clients cannot grow it without limit by sending random Mcp-Session-Id values.
	defaultMemorySessionMaxEntries = 100000
	// defaultMemorySessionTTL is the idle lifetime of a session entry.
	defaultMemorySessionTTL = 24 * time.Hour
)

// memorySession holds the state for a single session.
type memorySession struct {
	userID   string
	state    []byte
	lastSeen time.Time
}

// MemorySessionStore is an in-process SessionStore. Entries expire after an
// idle TTL (refreshed on access) and the store holds at most maxEntries; when
// full, expired entries are purged first and then the least recently used
// entry is evicted.
type MemorySessionStore struct {
	mu         sync.Mutex
	data       map[string]memorySession
	maxEntries int
	ttl        time.Duration
	now        func() time.Time
}

// NewMemorySessionStore creates an empty in-memory session store with default
// size and idle-TTL bounds.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		data:       make(map[string]memorySession),
		maxEntries: defaultMemorySessionMaxEntries,
		ttl:        defaultMemorySessionTTL,
		now:        time.Now,
	}
}

// expired reports whether sess has been idle longer than the TTL. Caller holds mu.
func (s *MemorySessionStore) expired(sess memorySession, now time.Time) bool {
	return s.ttl > 0 && now.Sub(sess.lastSeen) > s.ttl
}

// putLocked inserts or replaces an entry, enforcing the size bound. Caller holds mu.
func (s *MemorySessionStore) putLocked(sessionID, userID string, state []byte) {
	now := s.now()
	if _, exists := s.data[sessionID]; !exists && s.maxEntries > 0 && len(s.data) >= s.maxEntries {
		for id, sess := range s.data {
			if s.expired(sess, now) {
				delete(s.data, id)
			}
		}
		if len(s.data) >= s.maxEntries {
			var oldestID string
			var oldest time.Time
			for id, sess := range s.data {
				if oldestID == "" || sess.lastSeen.Before(oldest) {
					oldestID, oldest = id, sess.lastSeen
				}
			}
			delete(s.data, oldestID)
		}
	}
	s.data[sessionID] = memorySession{userID: userID, state: state, lastSeen: now}
}

// SaveSession stores or overwrites a session.
func (s *MemorySessionStore) SaveSession(_ context.Context, sessionID, userID string, state []byte) error {
	s.mu.Lock()
	s.putLocked(sessionID, userID, state)
	s.mu.Unlock()
	return nil
}

// SaveSessionIfAbsent atomically stores the session only when no live session
// exists under sessionID. It reports whether the session was stored.
func (s *MemorySessionStore) SaveSessionIfAbsent(_ context.Context, sessionID, userID string, state []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.data[sessionID]; ok && !s.expired(sess, s.now()) {
		return false, nil
	}
	s.putLocked(sessionID, userID, state)
	return true, nil
}

// GetSession returns the session state and user ID, refreshing its idle TTL.
func (s *MemorySessionStore) GetSession(_ context.Context, sessionID string) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.data[sessionID]
	if !ok {
		return nil, "", ErrSessionNotFound
	}
	now := s.now()
	if s.expired(sess, now) {
		delete(s.data, sessionID)
		return nil, "", ErrSessionNotFound
	}
	sess.lastSeen = now
	s.data[sessionID] = sess
	return sess.state, sess.userID, nil
}

// DeleteSession removes a session; deleting a missing session is not an error.
func (s *MemorySessionStore) DeleteSession(_ context.Context, sessionID string) error {
	s.mu.Lock()
	delete(s.data, sessionID)
	s.mu.Unlock()
	return nil
}
