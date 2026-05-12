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
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// RedisTokenStore is a Redis-backed implementation of EscalationTokenStore.
//
// Each caller's tokens are partitioned by a storage prefix derived from the
// request context (session ID or credential fingerprint). Two Redis key shapes
// are used:
//
//	{prefix}esc:tok:{userPrefix}:{jti}  JSON-encoded EscalationToken; TTL = token expiry
//	{prefix}esc:set:{userPrefix}        Redis Set of JTIs owned by this user/session
//
// When userPrefix is empty (unscoped), the simpler forms are used:
//
//	{prefix}esc:tok:{jti}
//	{prefix}esc:set:default
type RedisTokenStore struct {
	client   *redis.Client
	prefix   string         // global Redis namespace, e.g. "portcullis:"
	scope    string         // "session" | "fingerprint" | ""
	identity IdentitySource // used for fingerprint scope fallback
}

// NewRedisTokenStore creates a RedisTokenStore. prefix namespaces all Redis keys;
// if empty, "portcullis:" is used. scope and identity drive per-caller partitioning.
func NewRedisTokenStore(client *redis.Client, prefix, scope string, identity IdentitySource) *RedisTokenStore {
	if prefix == "" {
		prefix = defaultRedisKeyPrefix
	}
	return &RedisTokenStore{
		client:   client,
		prefix:   prefix,
		scope:    scope,
		identity: identity,
	}
}

func (s *RedisTokenStore) tokKey(userPrefix, jti string) string {
	if userPrefix == "" {
		return s.prefix + "esc:tok:" + jti
	}
	return s.prefix + "esc:tok:" + userPrefix + ":" + jti
}

func (s *RedisTokenStore) setKey(userPrefix string) string {
	if userPrefix == "" {
		return s.prefix + "esc:set:default"
	}
	return s.prefix + "esc:set:" + userPrefix
}

// All returns all valid (non-expired) escalation tokens for the current caller.
// The caller is identified via resolveStoragePrefix applied to ctx.
func (s *RedisTokenStore) All(ctx context.Context) []shared.EscalationToken {
	userPrefix := resolveStoragePrefix(ctx, s.scope, s.identity)
	setK := s.setKey(userPrefix)

	jtis, err := s.client.SMembers(ctx, setK).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			slog.Error("redis token store: SMEMBERS failed", "key", setK, "error", err)
		}
		return nil
	}
	if len(jtis) == 0 {
		return nil
	}

	// Pipeline GETs for all JTIs.
	pipe := s.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(jtis))
	for i, jti := range jtis {
		cmds[i] = pipe.Get(ctx, s.tokKey(userPrefix, jti))
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		slog.Error("redis token store: pipeline GET failed", "error", err)
		return nil
	}

	tokens := make([]shared.EscalationToken, 0, len(jtis))
	var stale []interface{}
	for i, cmd := range cmds {
		val, err := cmd.Result()
		if errors.Is(err, redis.Nil) {
			stale = append(stale, jtis[i])
			continue
		}
		if err != nil {
			slog.Error("redis token store: GET token failed", "jti", jtis[i], "error", err)
			continue
		}
		var tok shared.EscalationToken
		if err := json.Unmarshal([]byte(val), &tok); err != nil {
			slog.Error("redis token store: unmarshal token failed", "jti", jtis[i], "error", err)
			stale = append(stale, jtis[i])
			continue
		}
		tokens = append(tokens, tok)
	}

	if len(stale) > 0 {
		_ = s.client.SRem(ctx, setK, stale...).Err()
	}
	return tokens
}

// Add validates and stores a new escalation token, associating it with the
// current caller derived from ctx. Returns the parsed token on success.
func (s *RedisTokenStore) Add(ctx context.Context, raw string) (shared.EscalationToken, error) {
	tok, err := parseEscalationToken(raw)
	if err != nil {
		return shared.EscalationToken{}, fmt.Errorf("parse token: %w", err)
	}

	// Extract TTL from the JWT exp claim so the Redis key auto-expires.
	ttl := 24 * time.Hour // conservative default
	if claims, err := unsafeParseJWTClaims(raw); err == nil {
		if exp, ok := claims["exp"].(float64); ok {
			if d := time.Until(time.Unix(int64(exp), 0)); d > 0 {
				ttl = d
			}
		}
	}

	data, err := json.Marshal(tok)
	if err != nil {
		return shared.EscalationToken{}, fmt.Errorf("marshal token: %w", err)
	}

	userPrefix := resolveStoragePrefix(ctx, s.scope, s.identity)
	setK := s.setKey(userPrefix)

	pipe := s.client.Pipeline()
	pipe.Set(ctx, s.tokKey(userPrefix, tok.TokenID), data, ttl)
	pipe.SAdd(ctx, setK, tok.TokenID)
	pipe.Expire(ctx, setK, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return shared.EscalationToken{}, fmt.Errorf("redis store token: %w", err)
	}

	slog.Info("redis token store: stored escalation token", "jti", tok.TokenID)
	return tok, nil
}

// Delete removes the token with the given ID for the current caller.
func (s *RedisTokenStore) Delete(ctx context.Context, tokenID string) error {
	userPrefix := resolveStoragePrefix(ctx, s.scope, s.identity)
	setK := s.setKey(userPrefix)

	pipe := s.client.Pipeline()
	pipe.SRem(ctx, setK, tokenID)
	pipe.Del(ctx, s.tokKey(userPrefix, tokenID))
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("redis delete token %q: %w", tokenID, err)
	}
	return nil
}
