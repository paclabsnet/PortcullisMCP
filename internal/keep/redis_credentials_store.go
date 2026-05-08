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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultCredStorePrefix = "portcullis:keep:creds:"

// redisCredentialsStore is a cluster-safe CredentialsStore backed by Redis.
// It requires Redis 6.2+ for GETDEL support (used by ConsumePending).
type redisCredentialsStore struct {
	client redis.UniversalClient
	prefix string
}

// NewRedisCredentialsStore returns a CredentialsStore backed by a Redis client.
// keyPrefix is prepended to every key; pass "" to use the default prefix.
func NewRedisCredentialsStore(client redis.UniversalClient, keyPrefix string) CredentialsStore {
	if keyPrefix == "" {
		keyPrefix = defaultCredStorePrefix
	}
	return &redisCredentialsStore{client: client, prefix: keyPrefix}
}

func (s *redisCredentialsStore) redisTokenKey(backend, userID string) string {
	return s.prefix + "token:" + backend + ":" + userID
}

func (s *redisCredentialsStore) redisPendingKey(nonce string) string {
	return s.prefix + "pending:" + nonce
}

func (s *redisCredentialsStore) redisClientKey(backend string) string {
	return s.prefix + "client:" + backend
}

func (s *redisCredentialsStore) GetToken(ctx context.Context, backend, userID string) (*userToken, error) {
	data, err := s.client.Get(ctx, s.redisTokenKey(backend, userID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("redis get token: %w", err)
	}
	var t userToken
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("unmarshal token: %w", err)
	}
	return &t, nil
}

func (s *redisCredentialsStore) SetToken(ctx context.Context, backend, userID string, token *userToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}
	ttl := time.Until(token.Expiry)
	if ttl <= 0 {
		return nil // already expired; do not store
	}
	return s.client.Set(ctx, s.redisTokenKey(backend, userID), data, ttl).Err()
}

func (s *redisCredentialsStore) DeleteToken(ctx context.Context, backend, userID string) error {
	return s.client.Del(ctx, s.redisTokenKey(backend, userID)).Err()
}

// StorePending stores the pending OAuth flow state for nonce with the given TTL.
// A zero or negative ttl falls back to defaultPendingTTL (10 minutes).
// The nonce doubles as the OAuth state parameter.
func (s *redisCredentialsStore) StorePending(ctx context.Context, nonce string, p *pendingAuth, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = defaultPendingTTL
	}
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal pending: %w", err)
	}
	return s.client.Set(ctx, s.redisPendingKey(nonce), data, ttl).Err()
}

// ConsumePending atomically fetches and deletes the pending state for nonce
// using Redis GETDEL (requires Redis 6.2+). Returns (nil, nil) for unknown nonces.
func (s *redisCredentialsStore) ConsumePending(ctx context.Context, nonce string) (*pendingAuth, error) {
	data, err := s.client.GetDel(ctx, s.redisPendingKey(nonce)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("redis getdel pending: %w", err)
	}
	var p pendingAuth
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshal pending: %w", err)
	}
	return &p, nil
}

func (s *redisCredentialsStore) redisClientLockKey(backend string) string {
	return s.prefix + "dcr_lock:" + backend
}

func (s *redisCredentialsStore) redisDCRFailKey(backend string) string {
	return s.prefix + "dcr_fail:" + backend
}

func (s *redisCredentialsStore) GetClientReg(ctx context.Context, backend string) (*clientReg, error) {
	data, err := s.client.Get(ctx, s.redisClientKey(backend)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("redis get client reg: %w", err)
	}
	var r clientReg
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("unmarshal client reg: %w", err)
	}
	return &r, nil
}

// SetClientRegNX atomically sets the client registration only if no entry exists.
// Uses Redis SET NX (not-exists) to prevent overwriting a concurrent winner.
// Client registrations do not expire (TTL=0).
func (s *redisCredentialsStore) SetClientRegNX(ctx context.Context, backend string, reg *clientReg) (bool, error) {
	data, err := json.Marshal(reg)
	if err != nil {
		return false, fmt.Errorf("marshal client reg: %w", err)
	}
	ok, err := s.client.SetNX(ctx, s.redisClientKey(backend), data, 0).Result()
	if err != nil {
		return false, fmt.Errorf("redis setnx client reg: %w", err)
	}
	return ok, nil
}

// LockDCR acquires a short-lived distributed lock for the backend's DCR flow.
// Uses Redis SET NX EX with a 30-second TTL to guard against lock holder crashes.
func (s *redisCredentialsStore) LockDCR(ctx context.Context, backend string) (func(), error) {
	const lockTTL = 30 * time.Second
	key := s.redisClientLockKey(backend)
	ok, err := s.client.SetNX(ctx, key, "1", lockTTL).Result()
	if err != nil {
		return nil, fmt.Errorf("redis dcr lock acquire: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("dcr lock for %q already held", backend)
	}
	return func() {
		s.client.Del(ctx, key) //nolint:errcheck
	}, nil
}

// GetDCRFailure returns the cached DCR failure reason, or "" if none exists.
func (s *redisCredentialsStore) GetDCRFailure(ctx context.Context, backend string) (string, error) {
	val, err := s.client.Get(ctx, s.redisDCRFailKey(backend)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", nil
		}
		return "", fmt.Errorf("redis get dcr failure: %w", err)
	}
	return val, nil
}

// SetDCRFailure caches a DCR failure reason with the given TTL.
func (s *redisCredentialsStore) SetDCRFailure(ctx context.Context, backend string, reason string, ttl time.Duration) error {
	return s.client.Set(ctx, s.redisDCRFailKey(backend), reason, ttl).Err()
}
