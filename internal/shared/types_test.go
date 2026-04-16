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

package shared

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorTypes(t *testing.T) {
	t.Run("IdentityVerificationError", func(t *testing.T) {
		err := &IdentityVerificationError{Reason: "fail"}
		assert.Equal(t, "fail", err.Error())
		assert.True(t, errors.Is(err, ErrIdentityVerificationFailed))
		assert.Equal(t, ErrIdentityVerificationFailed, err.Unwrap())

		errEmpty := &IdentityVerificationError{}
		assert.Equal(t, ErrIdentityVerificationFailed.Error(), errEmpty.Error())
	})

	t.Run("DenyError", func(t *testing.T) {
		err := &DenyError{Reason: "no"}
		assert.Contains(t, err.Error(), "no")
		assert.True(t, errors.Is(err, ErrDenied))
		assert.Equal(t, ErrDenied, err.Unwrap())

		errEmpty := &DenyError{}
		assert.Equal(t, ErrDenied.Error(), errEmpty.Error())
	})

	t.Run("SessionUnknownError", func(t *testing.T) {
		err := &SessionUnknownError{SessionID: "123", Reason: "unknown"}
		assert.Contains(t, err.Error(), "unknown")
		assert.True(t, errors.Is(err, ErrSessionUnknown))
		assert.Equal(t, ErrSessionUnknown, err.Unwrap())

		errEmpty := &SessionUnknownError{}
		assert.Equal(t, ErrSessionUnknown.Error(), errEmpty.Error())
	})

	t.Run("EscalationPendingError", func(t *testing.T) {
		err := &EscalationPendingError{EscalationJTI: "jti123", Reason: "waiting"}
		assert.Contains(t, err.Error(), "waiting")
		assert.True(t, errors.Is(err, ErrEscalationPending))
		assert.Equal(t, ErrEscalationPending, err.Unwrap())

		errEmpty := &EscalationPendingError{}
		assert.Contains(t, errEmpty.Error(), "Escalation required")
	})
}
