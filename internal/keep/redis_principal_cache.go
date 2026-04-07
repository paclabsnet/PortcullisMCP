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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

const defaultKeepKeyPrefix = "portcullis:keep:"

// RedisPrincipalCache implements PrincipalCacher using Redis.
// Cache misses and Redis errors on Get return (zero, false); errors on Add are
// logged and swallowed so a Redis hiccup never blocks a legitimate request.
type RedisPrincipalCache struct {
	client *redis.Client
	prefix string
}

// NewRedisPrincipalCache creates a RedisPrincipalCache backed by an existing
// redis.Client. keyPrefix is prepended to every key; pass "" for the default.
func NewRedisPrincipalCache(client *redis.Client, keyPrefix string) *RedisPrincipalCache {
	if keyPrefix == "" {
		keyPrefix = defaultKeepKeyPrefix
	}
	return &RedisPrincipalCache{client: client, prefix: keyPrefix}
}

func (c *RedisPrincipalCache) key(cacheKey string) string {
	return c.prefix + "normalized:" + cacheKey
}

// Get returns the cached Principal for key, or (zero, false) on miss or error.
func (c *RedisPrincipalCache) Get(key string) (shared.Principal, bool) {
	val, err := c.client.Get(context.Background(), c.key(key)).Bytes()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			slog.Warn("keep: redis principal cache get error", "err", err)
		}
		return shared.Principal{}, false
	}
	var p shared.Principal
	if err := json.Unmarshal(val, &p); err != nil {
		slog.Warn("keep: redis principal cache unmarshal error", "err", err)
		return shared.Principal{}, false
	}
	return p, true
}

// Add stores principal in Redis under key with the given TTL.
// If TTL is zero or negative the entry is not stored.
// Errors are logged and swallowed — a cache write failure is non-fatal.
func (c *RedisPrincipalCache) Add(key string, principal shared.Principal, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	data, err := json.Marshal(principal)
	if err != nil {
		slog.Warn("keep: redis principal cache marshal error", "err", err)
		return
	}
	if err := c.client.Set(context.Background(), c.key(key), data, ttl).Err(); err != nil {
		slog.Warn("keep: redis principal cache set error", "err", err)
	}
}

// newKeepRedisClient constructs and validates a Redis client from cfg.
// Returns an error if the server cannot be reached.
func newKeepRedisClient(ctx context.Context, cfg RedisConfig) (*redis.Client, error) {
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
			slog.Warn("keep: redis TLS certificate verification is disabled — do not use in production")
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
