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
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisExchangeKeyPrefix = "portcullis:keep:exchange:"

// IdentityExchangeCacher is the interface satisfied by any identity exchange cache backend.
// Implementations must be safe for concurrent use.
type IdentityExchangeCacher interface {
	// Get returns a cached exchanged identity value and true if a valid (non-expired) entry exists.
	Get(key string) (string, bool)
	// Add inserts or updates a value with the given TTL.
	Add(key string, value string, ttl time.Duration)
}

// IdentityExchangeCache is a thread-safe LRU cache of exchanged identity values with TTL expiry.
// When the cache is at capacity, the least recently used entry is evicted.
type IdentityExchangeCache struct {
	mu         sync.Mutex
	maxEntries int
	cache      map[string]*list.Element
	ll         *list.List
}

type identityExchangeEntry struct {
	key    string
	value  string
	expiry time.Time
}

// NewIdentityExchangeCache returns a new IdentityExchangeCache limited to maxEntries entries.
// maxEntries must be greater than zero.
func NewIdentityExchangeCache(maxEntries int) *IdentityExchangeCache {
	return &IdentityExchangeCache{
		maxEntries: maxEntries,
		cache:      make(map[string]*list.Element),
		ll:         list.New(),
	}
}

// Get returns a cached value and true if a valid (non-expired) entry exists for key.
// Expired entries are removed and false is returned.
func (c *IdentityExchangeCache) Get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ele, hit := c.cache[key]
	if !hit {
		return "", false
	}
	e := ele.Value.(*identityExchangeEntry)
	if time.Now().After(e.expiry) {
		c.removeElement(ele)
		return "", false
	}
	c.ll.MoveToFront(ele)
	return e.value, true
}

// Add inserts or updates a value in the cache with the given TTL. If TTL is
// zero or negative the entry is not stored. If the cache is already at
// capacity, the least recently used entry is evicted first.
func (c *IdentityExchangeCache) Add(key string, value string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, hit := c.cache[key]; hit {
		c.ll.MoveToFront(ele)
		e := ele.Value.(*identityExchangeEntry)
		e.value = value
		e.expiry = time.Now().Add(ttl)
		return
	}
	ele := c.ll.PushFront(&identityExchangeEntry{
		key:    key,
		value:  value,
		expiry: time.Now().Add(ttl),
	})
	c.cache[key] = ele
	if c.ll.Len() > c.maxEntries {
		c.removeOldest()
	}
}

// Len returns the number of entries currently in the cache, including expired ones.
func (c *IdentityExchangeCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func (c *IdentityExchangeCache) removeOldest() {
	if ele := c.ll.Back(); ele != nil {
		c.removeElement(ele)
	}
}

func (c *IdentityExchangeCache) removeElement(ele *list.Element) {
	c.ll.Remove(ele)
	delete(c.cache, ele.Value.(*identityExchangeEntry).key)
}

// RedisIdentityExchangeCache implements IdentityExchangeCacher using Redis.
// Cache misses and Redis errors on Get return ("", false); errors on Add are
// logged and swallowed so a Redis hiccup never blocks a legitimate request.
type RedisIdentityExchangeCache struct {
	client      *redis.Client
	prefix      string
	backendName string
}

// NewRedisIdentityExchangeCache creates a RedisIdentityExchangeCache backed by an
// existing redis.Client. keyPrefix is prepended to every key; pass "" for the default.
// backendName is included in error log entries for observability.
func NewRedisIdentityExchangeCache(client *redis.Client, keyPrefix, backendName string) *RedisIdentityExchangeCache {
	if keyPrefix == "" {
		keyPrefix = redisExchangeKeyPrefix
	}
	return &RedisIdentityExchangeCache{client: client, prefix: keyPrefix, backendName: backendName}
}

func (c *RedisIdentityExchangeCache) key(cacheKey string) string {
	return c.prefix + cacheKey
}

// Get returns the cached value for key, or ("", false) on miss or error.
func (c *RedisIdentityExchangeCache) Get(key string) (string, bool) {
	val, err := c.client.Get(context.Background(), c.key(key)).Bytes()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			slog.Warn("keep: redis identity exchange cache get error", "backend", c.backendName, "err", err)
		}
		return "", false
	}
	var result string
	if err := json.Unmarshal(val, &result); err != nil {
		slog.Warn("keep: redis identity exchange cache unmarshal error", "backend", c.backendName, "err", err)
		return "", false
	}
	return result, true
}

// Add stores value in Redis under key with the given TTL.
// If TTL is zero or negative the entry is not stored.
// Errors are logged and swallowed — a cache write failure is non-fatal.
func (c *RedisIdentityExchangeCache) Add(key string, value string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	data, err := json.Marshal(value)
	if err != nil {
		slog.Warn("keep: redis identity exchange cache marshal error", "backend", c.backendName, "err", err)
		return
	}
	if err := c.client.Set(context.Background(), c.key(key), data, ttl).Err(); err != nil {
		slog.Warn("keep: redis identity exchange cache set error", "backend", c.backendName, "err", err)
	}
}
