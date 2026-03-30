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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// defaultKeyPrefix is prepended to every Redis key Guard writes.
const defaultKeyPrefix = "portcullis:guard:"

// addUnclaimedScript atomically checks the per-user capacity limit, stores the
// token, and updates the user-set in a single round-trip using a Lua script.
//
// KEYS[1] = token key   (prefix + "unclaimed:tok:" + jti)
// KEYS[2] = user-set key (prefix + "unclaimed:usr:" + userID)
// ARGV[1] = JSON-encoded UnclaimedToken
// ARGV[2] = TTL in milliseconds (string-encoded int64)
// ARGV[3] = JTI (added to user set)
// ARGV[4] = max per-user limit  (0 = unlimited)
var addUnclaimedScript = redis.NewScript(`
local count = redis.call('SCARD', KEYS[2])
if tonumber(ARGV[4]) > 0 and count >= tonumber(ARGV[4]) then
    return redis.error_reply('CAPACITY_EXCEEDED')
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SADD', KEYS[2], ARGV[3])
local cur = redis.call('PTTL', KEYS[2])
if cur < tonumber(ARGV[2]) then
    redis.call('PEXPIRE', KEYS[2], ARGV[2])
end
return 1
`)

// NewRedisClient constructs and validates a Redis client from cfg.
// Returns an error immediately if the Redis server cannot be reached.
func NewRedisClient(ctx context.Context, cfg RedisConfig) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	}

	if cfg.TLSEnabled {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec — user-controlled; warn below
		}
		if cfg.TLSSkipVerify {
			slog.Warn("redis TLS certificate verification is disabled — do not use in production")
		}
		if cfg.TLSCACert != "" {
			pem, err := os.ReadFile(cfg.TLSCACert)
			if err != nil {
				return nil, fmt.Errorf("read redis TLS CA cert %q: %w", cfg.TLSCACert, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("parse redis TLS CA cert %q: no valid PEM blocks found", cfg.TLSCACert)
			}
			tlsCfg.RootCAs = pool
		}
		opts.TLSConfig = tlsCfg
	}

	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect to redis at %q: %w", cfg.Addr, err)
	}
	return client, nil
}

// ---- RedisPendingStore ------------------------------------------------------

// RedisPendingStore implements PendingStore using Redis.
// Each pending request is stored as a JSON value at a TTL-bearing key.
// PurgeExpired is a no-op because Redis expires keys automatically.
type RedisPendingStore struct {
	client *redis.Client
	prefix string
}

// NewRedisPendingStore creates a RedisPendingStore backed by client.
// keyPrefix is prepended to every key; pass "" to use the default.
func NewRedisPendingStore(client *redis.Client, keyPrefix string) *RedisPendingStore {
	if keyPrefix == "" {
		keyPrefix = defaultKeyPrefix
	}
	return &RedisPendingStore{client: client, prefix: keyPrefix}
}

func (s *RedisPendingStore) pendingKey(jti string) string {
	return s.prefix + "pending:" + jti
}

func (s *RedisPendingStore) StorePending(ctx context.Context, req PendingRequest) error {
	ttl := time.Until(req.ExpiresAt)
	if ttl <= 0 {
		// Already expired — nothing to store.
		return nil
	}
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal pending request: %w", err)
	}

	slog.Debug("StorePending: ", "req", data)
	return s.client.Set(ctx, s.pendingKey(req.JTI), data, ttl).Err()
}

func (s *RedisPendingStore) GetPending(ctx context.Context, jti string) (PendingRequest, bool, error) {
	val, err := s.client.Get(ctx, s.pendingKey(jti)).Result()
	if errors.Is(err, redis.Nil) {
		return PendingRequest{}, false, nil
	}
	if err != nil {
		return PendingRequest{}, false, fmt.Errorf("redis get pending %q: %w", jti, err)
	}

	slog.Debug("GetPending: ", "val", val)
	var req PendingRequest
	if err := json.Unmarshal([]byte(val), &req); err != nil {
		return PendingRequest{}, false, fmt.Errorf("unmarshal pending request %q: %w", jti, err)
	}
	return req, true, nil
}

// PurgeExpired is a no-op: Redis removes expired keys automatically via TTL.
func (s *RedisPendingStore) PurgeExpired(_ context.Context) error { return nil }

// ---- RedisUnclaimedStore ----------------------------------------------------

// RedisUnclaimedStore implements UnclaimedStore using Redis.
//
// Key layout:
//
//	{prefix}unclaimed:tok:{jti}     JSON-encoded UnclaimedToken, TTL-bearing
//	{prefix}unclaimed:usr:{userID}  Redis Set of JTIs; TTL extended on each add
//
// AddUnclaimed uses a Lua script for an atomic capacity-check-and-set.
// ClaimToken uses GETDEL (Redis 6.2+) for an atomic read-and-delete, preventing
// double-claiming across multiple Guard instances.
// PurgeExpired is a no-op; token keys expire automatically, and stale JTIs are
// removed from user sets lazily during ListUnclaimed.
//
// Note: the total-unclaimed-across-all-users limit (LimitsConfig.MaxUnclaimedTotal)
// is not enforced by this store because doing so atomically would require a
// global Redis counter, which adds coordination overhead and is better handled by
// configuring Redis maxmemory. The per-user limit is enforced atomically.
type RedisUnclaimedStore struct {
	client     *redis.Client
	prefix     string
	maxPerUser int // 0 = unlimited; enforced inside Lua script
}

// NewRedisUnclaimedStore creates a RedisUnclaimedStore backed by client.
// keyPrefix is prepended to every key; pass "" to use the default.
// maxPerUser caps the number of unclaimed tokens per user; 0 is unlimited.
func NewRedisUnclaimedStore(client *redis.Client, keyPrefix string, maxPerUser int) *RedisUnclaimedStore {
	if keyPrefix == "" {
		keyPrefix = defaultKeyPrefix
	}
	return &RedisUnclaimedStore{client: client, prefix: keyPrefix, maxPerUser: maxPerUser}
}

func (s *RedisUnclaimedStore) tokKey(jti string) string {
	return s.prefix + "unclaimed:tok:" + jti
}

func (s *RedisUnclaimedStore) usrKey(userID string) string {
	return s.prefix + "unclaimed:usr:" + userID
}

func (s *RedisUnclaimedStore) AddUnclaimed(ctx context.Context, tok UnclaimedToken) error {
	ttl := time.Until(tok.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	data, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("marshal unclaimed token: %w", err)
	}

	slog.Debug("AddUnclaimed: ", "tok", data)

	ttlMs := ttl.Milliseconds()
	err = addUnclaimedScript.Run(ctx, s.client,
		[]string{s.tokKey(tok.JTI), s.usrKey(tok.UserID)},
		string(data),
		ttlMs,
		tok.JTI,
		s.maxPerUser,
	).Err()
	if err != nil && strings.Contains(err.Error(), "CAPACITY_EXCEEDED") {
		return ErrCapacityExceeded
	}
	return err
}

func (s *RedisUnclaimedStore) ListUnclaimed(ctx context.Context, userID string) ([]UnclaimedToken, error) {
	jtis, err := s.client.SMembers(ctx, s.usrKey(userID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("redis smembers user %q: %w", userID, err)
	}

	slog.Debug("ListUnclaimed: ", "userId", userID, "jti count:", len(jtis))

	if len(jtis) == 0 {
		return nil, nil
	}

	// Pipeline GETs for all JTIs in one round-trip.
	pipe := s.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(jtis))
	for i, jti := range jtis {
		cmds[i] = pipe.Get(ctx, s.tokKey(jti))
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("redis pipeline get tokens for user %q: %w", userID, err)
	}

	result := make([]UnclaimedToken, 0, len(jtis))
	var stale []interface{}
	for i, cmd := range cmds {
		val, err := cmd.Result()
		if errors.Is(err, redis.Nil) {
			// Token key has expired but JTI lingers in the user set — clean up lazily.
			stale = append(stale, jtis[i])
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("redis get token %q: %w", jtis[i], err)
		}
		var tok UnclaimedToken
		if err := json.Unmarshal([]byte(val), &tok); err != nil {
			return nil, fmt.Errorf("unmarshal token %q: %w", jtis[i], err)
		}
		result = append(result, tok)
	}

	if len(stale) > 0 {
		// Best-effort lazy cleanup of stale JTIs from the user set.
		_ = s.client.SRem(ctx, s.usrKey(userID), stale...).Err()
	}
	return result, nil
}

func (s *RedisUnclaimedStore) ClaimToken(ctx context.Context, jti string) (*UnclaimedToken, error) {
	// GETDEL is atomic in Redis: only one caller wins, preventing double-claiming.
	val, err := s.client.GetDel(ctx, s.tokKey(jti)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis getdel token %q: %w", jti, err)
	}

	slog.Debug("ClaimToken: ", "jti", jti, "val", val)

	var tok UnclaimedToken
	if err := json.Unmarshal([]byte(val), &tok); err != nil {
		return nil, fmt.Errorf("unmarshal claimed token %q: %w", jti, err)
	}

	// Best-effort removal of the JTI from the user set; not critical for
	// correctness since ClaimToken is only ever called once per JTI.
	_ = s.client.SRem(ctx, s.usrKey(tok.UserID), jti).Err()

	return &tok, nil
}

// PurgeExpired is a no-op: token keys expire automatically via Redis TTL.
// Stale user-set entries are cleaned up lazily inside ListUnclaimed.
func (s *RedisUnclaimedStore) PurgeExpired(_ context.Context) error { return nil }
