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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisPendingStore is a Redis-backed implementation of PendingEscalationStore.
// Keys are namespaced under {prefix}pnd:{key} where key already includes the
// per-session or per-fingerprint prefix from EscalationManager.pendingKey.
type RedisPendingStore struct {
	client *redis.Client
	prefix string // e.g. "portcullis:"
}

// NewRedisPendingStore creates a RedisPendingStore using the given Redis client.
// prefix namespaces all keys; if empty, "portcullis:" is used.
func NewRedisPendingStore(client *redis.Client, prefix string) *RedisPendingStore {
	if prefix == "" {
		prefix = defaultRedisKeyPrefix
	}
	return &RedisPendingStore{client: client, prefix: prefix}
}

func (s *RedisPendingStore) key(k string) string {
	return s.prefix + "pnd:" + k
}

// Store persists a pending escalation with a TTL derived from p.ExpiresAt.
func (s *RedisPendingStore) Store(ctx context.Context, key string, p pendingEscalation) {
	data, err := json.Marshal(p)
	if err != nil {
		slog.Error("redis pending store: marshal failed", "key", key, "error", err)
		return
	}
	ttl := time.Until(p.ExpiresAt)
	if ttl <= 0 {
		return // already expired — no-op
	}
	if err := s.client.Set(ctx, s.key(key), data, ttl).Err(); err != nil {
		slog.Error("redis pending store: SET failed", "key", key, "error", err)
	}
}

// Get retrieves a pending escalation by its partitioned key.
// Returns (zero, false) if not found or expired.
func (s *RedisPendingStore) Get(ctx context.Context, key string) (pendingEscalation, bool) {
	val, err := s.client.Get(ctx, s.key(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return pendingEscalation{}, false
	}
	if err != nil {
		slog.Error("redis pending store: GET failed", "key", key, "error", fmt.Sprintf("%v", err))
		return pendingEscalation{}, false
	}
	var p pendingEscalation
	if err := json.Unmarshal(val, &p); err != nil {
		slog.Error("redis pending store: unmarshal failed", "key", key, "error", err)
		return pendingEscalation{}, false
	}
	return p, true
}

// Delete removes a pending escalation by its partitioned key.
func (s *RedisPendingStore) Delete(ctx context.Context, key string) {
	if err := s.client.Del(ctx, s.key(key)).Err(); err != nil && !errors.Is(err, redis.Nil) {
		slog.Error("redis pending store: DEL failed", "key", key, "error", err)
	}
}
