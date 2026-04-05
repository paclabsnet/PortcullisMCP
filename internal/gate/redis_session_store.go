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
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisSessionPrefix = "portcullis:session:"
)

// redisSessionValue is the JSON payload stored in Redis for each session.
type redisSessionValue struct {
	UserID string `json:"user_id"`
	State  []byte `json:"state"`
}

// RedisSessionStore is a Redis-backed implementation of SessionStore with TTL.
type RedisSessionStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewRedisSessionStore creates a RedisSessionStore using the given Redis address
// and session TTL in seconds.
func NewRedisSessionStore(addr string, ttlSeconds int) *RedisSessionStore {
	client := redis.NewClient(&redis.Options{Addr: addr})
	return &RedisSessionStore{
		client: client,
		ttl:    time.Duration(ttlSeconds) * time.Second,
	}
}

// NewRedisSessionStoreFromClient creates a RedisSessionStore using a pre-built
// redis.Client. Useful for testing with miniredis.
func NewRedisSessionStoreFromClient(client *redis.Client, ttlSeconds int) *RedisSessionStore {
	return &RedisSessionStore{
		client: client,
		ttl:    time.Duration(ttlSeconds) * time.Second,
	}
}

func (s *RedisSessionStore) key(sessionID string) string {
	return redisSessionPrefix + sessionID
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
