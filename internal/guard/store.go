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
	"errors"
	"time"
)

// ErrCapacityExceeded is returned by store operations when the configured
// capacity limit would be exceeded by the requested operation.
var ErrCapacityExceeded = errors.New("store capacity exceeded")

// PendingRequest is a Keep-signed escalation request JWT registered by Gate
// before it presents the approval URL to the user.  Storing it here allows the
// approval page to be served from a short ?jti= URL without embedding the full
// JWT in the query string.
type PendingRequest struct {
	JTI       string
	JWT       string
	ExpiresAt time.Time
}

// UnclaimedToken is a Guard-issued escalation token that has been approved by
// the user but not yet collected by Gate.
type UnclaimedToken struct {
	UserID    string
	JTI       string
	Raw       string
	ExpiresAt time.Time
}

// PendingStore manages pending escalation request JWTs.
// All methods must be safe for concurrent use.
//
// The built-in implementation (NewMemPendingStore) stores entries in a
// process-local map protected by a mutex.  A distributed implementation
// (e.g. Redis) would store entries with a server-side TTL and share state
// across multiple Guard instances, making PurgeExpired a no-op.
type PendingStore interface {
	// StorePending stores a pending escalation request.
	// Returns ErrCapacityExceeded if the store is at the configured limit.
	StorePending(ctx context.Context, req PendingRequest) error

	// GetPending retrieves a pending request by JTI.
	// Returns (zero, false, nil) if the entry does not exist or has expired.
	GetPending(ctx context.Context, jti string) (PendingRequest, bool, error)

	// PurgeExpired removes expired entries.
	// Implementations that manage expiry natively (e.g. Redis TTL) may treat
	// this as a no-op.
	PurgeExpired(ctx context.Context) error
}

// UnclaimedStore manages approved escalation tokens awaiting collection by Gate.
// All methods must be safe for concurrent use.
//
// The built-in implementation (NewMemUnclaimedStore) stores tokens in a
// process-local nested map.  A distributed implementation would store tokens
// with a server-side TTL and implement ClaimToken as an atomic
// compare-and-delete (e.g. a Lua script in Redis) to prevent double-claiming
// across multiple Guard instances.
type UnclaimedStore interface {
	// AddUnclaimed stores an approved escalation token.
	// Returns ErrCapacityExceeded if the per-user or total capacity limit
	// would be exceeded.
	AddUnclaimed(ctx context.Context, tok UnclaimedToken) error

	// ListUnclaimed returns all non-expired unclaimed tokens for userID.
	// Returns an empty slice (not an error) when the user has no tokens.
	ListUnclaimed(ctx context.Context, userID string) ([]UnclaimedToken, error)

	// ClaimToken atomically removes and returns the token with the given JTI.
	// Returns (nil, nil) if the token is not found — it may not yet be
	// approved, may already have been claimed, or may have expired.
	// Each token may only be claimed once.
	ClaimToken(ctx context.Context, jti string) (*UnclaimedToken, error)

	// PurgeExpired removes expired entries.
	// Implementations that manage expiry natively (e.g. Redis TTL) may treat
	// this as a no-op.
	PurgeExpired(ctx context.Context) error
}
