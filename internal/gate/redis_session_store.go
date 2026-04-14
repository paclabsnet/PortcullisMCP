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
	"iter"
	"time"

	"github.com/redis/go-redis/v9"
)

// defaultRedisKeyPrefix is the namespace prefix used when RedisConfig.KeyPrefix is empty.
const defaultRedisKeyPrefix = "portcullis:"

// RedisConfig holds all connection and namespace settings for a Redis-backed store.
// Fields map directly to the keys in operations.storage.config in gate.yaml.
type RedisConfig struct {
	Addr      string // required; e.g. "localhost:6379"
	Password  string // optional; empty = no auth
	DB        int    // optional; 0 = default Redis database
	KeyPrefix string // optional; namespaces all keys; defaults to "portcullis:"
}

// redisSessionValue is the JSON payload stored in Redis for each session.
type redisSessionValue struct {
	UserID string `json:"user_id"`
	State  []byte `json:"state"`
}

// RedisSessionStore is a Redis-backed implementation of SessionStore with TTL.
type RedisSessionStore struct {
	client    *redis.Client
	ttl       time.Duration
	keyPrefix string
}

// NewRedisSessionStore creates a RedisSessionStore from a RedisConfig.
// All Config fields (password, db, key_prefix) are honoured; addr is required.
// A Ping is performed at construction time; if Redis is unreachable the client
// is closed and an error is returned so the process fails fast at startup.
func NewRedisSessionStore(ctx context.Context, cfg RedisConfig, ttlSeconds int) (*RedisSessionStore, error) {
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = defaultRedisKeyPrefix
	}
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("gate: redis unavailable at %q: %w", cfg.Addr, err)
	}
	return &RedisSessionStore{
		client:    client,
		ttl:       time.Duration(ttlSeconds) * time.Second,
		keyPrefix: prefix,
	}, nil
}

// NewRedisSessionStoreFromClient creates a RedisSessionStore using a pre-built
// redis.Client. The default key prefix is applied. Useful for testing with miniredis.
func NewRedisSessionStoreFromClient(client *redis.Client, ttlSeconds int) *RedisSessionStore {
	return &RedisSessionStore{
		client:    client,
		ttl:       time.Duration(ttlSeconds) * time.Second,
		keyPrefix: defaultRedisKeyPrefix,
	}
}

func (s *RedisSessionStore) key(sessionID string) string {
	return s.keyPrefix + "session:" + sessionID
}

// SaveSession stores the session in Redis with the configured TTL.
func (s *RedisSessionStore) SaveSession(ctx context.Context, sessionID, userID string, state []byte) error {
	val := redisSessionValue{UserID: userID, State: state}
	data, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	if err := s.client.Set(ctx, s.key(sessionID), data, s.ttl).Err(); err != nil {
		return fmt.Errorf("redis set session: %w", err)
	}
	return nil
}

// GetSession retrieves the session from Redis.
// Returns ErrSessionNotFound if the key does not exist or has expired.
func (s *RedisSessionStore) GetSession(ctx context.Context, sessionID string) ([]byte, string, error) {
	data, err := s.client.Get(ctx, s.key(sessionID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, "", ErrSessionNotFound
		}
		return nil, "", fmt.Errorf("redis get session: %w", err)
	}
	var val redisSessionValue
	if err := json.Unmarshal(data, &val); err != nil {
		return nil, "", fmt.Errorf("unmarshal session: %w", err)
	}
	return val.State, val.UserID, nil
}

// DeleteSession removes the session from Redis.
func (s *RedisSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	if err := s.client.Del(ctx, s.key(sessionID)).Err(); err != nil {
		return fmt.Errorf("redis del session: %w", err)
	}
	return nil
}

// eventKey returns the Redis key for an SSE event list.
func (s *RedisSessionStore) eventKey(sessionID, streamID string) string {
	return s.keyPrefix + "events:" + sessionID + ":" + streamID
}

// Open implements mcp.EventStore.Open. Redis lists are created lazily on the
// first RPUSH, so no initialisation is required.
func (s *RedisSessionStore) Open(_ context.Context, _, _ string) error {
	return nil
}

// Append implements mcp.EventStore.Append by pushing data onto a Redis List
// and refreshing the TTL of that list.
func (s *RedisSessionStore) Append(ctx context.Context, sessionID, streamID string, data []byte) error {
	key := s.eventKey(sessionID, streamID)
	if err := s.client.RPush(ctx, key, data).Err(); err != nil {
		return fmt.Errorf("redis rpush event: %w", err)
	}
	if err := s.client.Expire(ctx, key, s.ttl).Err(); err != nil {
		return fmt.Errorf("redis expire event: %w", err)
	}
	return nil
}

// After implements mcp.EventStore.After. It returns an iterator over all data
// items in the stream whose zero-based position is greater than index.
//
// Because this implementation does not purge items from the list, ErrEventsPurged
// is never returned. LRANGE on a non-existent key returns an empty slice
// (not an error), which is the correct behaviour for an empty or unwritten stream.
func (s *RedisSessionStore) After(ctx context.Context, sessionID, streamID string, index int) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		key := s.eventKey(sessionID, streamID)
		start := int64(index + 1)
		items, err := s.client.LRange(ctx, key, start, -1).Result()
		if err != nil {
			yield(nil, fmt.Errorf("redis lrange events: %w", err))
			return
		}
		for _, item := range items {
			if !yield([]byte(item), nil) {
				return
			}
		}
	}
}

// SessionClosed implements mcp.EventStore.SessionClosed. It scans for and
// deletes all event-list keys belonging to the given session.
func (s *RedisSessionStore) SessionClosed(ctx context.Context, sessionID string) error {
	pattern := s.keyPrefix + "events:" + sessionID + ":*"
	var cursor uint64
	for {
		keys, next, err := s.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("redis scan events: %w", err)
		}
		if len(keys) > 0 {
			if err := s.client.Del(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("redis del events: %w", err)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return nil
}
