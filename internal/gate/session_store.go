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
	"errors"
)

// ErrSessionNotFound is returned when a session does not exist in the store.
var ErrSessionNotFound = errors.New("session not found")

// SessionStore manages stateful session storage for Gate.
type SessionStore interface {
	SaveSession(ctx context.Context, sessionID, userID string, state []byte) error
	GetSession(ctx context.Context, sessionID string) (state []byte, userID string, err error)
	DeleteSession(ctx context.Context, sessionID string) error
}
