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
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestMemorySessionStore(t *testing.T) {
	ctx := context.Background()

	t.Run("save and get round-trips correctly", func(t *testing.T) {
		s := NewMemorySessionStore()
		state := []byte(`{"fingerprint":"abc123"}`)
		if err := s.SaveSession(ctx, "sess-1", "user-a", state); err != nil {
			t.Fatalf("SaveSession: %v", err)
		}
		gotState, gotUser, err := s.GetSession(ctx, "sess-1")
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if gotUser != "user-a" {
			t.Errorf("userID = %q, want %q", gotUser, "user-a")
		}
		if !bytes.Equal(gotState, state) {
			t.Errorf("state = %q, want %q", gotState, state)
		}
	})

	t.Run("missing session returns ErrSessionNotFound", func(t *testing.T) {
		s := NewMemorySessionStore()
		_, _, err := s.GetSession(ctx, "nonexistent")
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("expected ErrSessionNotFound, got: %v", err)
		}
	})

	t.Run("delete removes session", func(t *testing.T) {
		s := NewMemorySessionStore()
		_ = s.SaveSession(ctx, "sess-del", "user-b", []byte("state"))
		if err := s.DeleteSession(ctx, "sess-del"); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		_, _, err := s.GetSession(ctx, "sess-del")
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("expected ErrSessionNotFound after delete, got: %v", err)
		}
	})

	t.Run("delete of nonexistent session is not an error", func(t *testing.T) {
		s := NewMemorySessionStore()
		if err := s.DeleteSession(ctx, "does-not-exist"); err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("overwrite updates state and userID", func(t *testing.T) {
		s := NewMemorySessionStore()
		_ = s.SaveSession(ctx, "sess-overwrite", "user-old", []byte("old"))
		_ = s.SaveSession(ctx, "sess-overwrite", "user-new", []byte("new"))
		gotState, gotUser, err := s.GetSession(ctx, "sess-overwrite")
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if gotUser != "user-new" {
			t.Errorf("userID = %q, want %q", gotUser, "user-new")
		}
		if string(gotState) != "new" {
			t.Errorf("state = %q, want %q", gotState, "new")
		}
	})

	t.Run("concurrent save and get", func(t *testing.T) {
		s := NewMemorySessionStore()
		const goroutines = 50
		var wg sync.WaitGroup
		wg.Add(goroutines * 2)

		// Writers
		for i := range goroutines {
			go func(i int) {
				defer wg.Done()
				id := fmt.Sprintf("sess-%d", i)
				_ = s.SaveSession(ctx, id, fmt.Sprintf("user-%d", i), []byte(id))
			}(i)
		}

		// Concurrent readers — may get ErrSessionNotFound if writer hasn't run yet; that's fine.
		for i := range goroutines {
			go func(i int) {
				defer wg.Done()
				id := fmt.Sprintf("sess-%d", i)
				_, _, _ = s.GetSession(ctx, id)
			}(i)
		}

		wg.Wait()

		// After all goroutines finish, every key written must be readable.
		for i := range goroutines {
			id := fmt.Sprintf("sess-%d", i)
			gotState, gotUser, err := s.GetSession(ctx, id)
			if err != nil {
				t.Errorf("GetSession(%q) after concurrent writes: %v", id, err)
				continue
			}
			if gotUser != fmt.Sprintf("user-%d", i) {
				t.Errorf("userID = %q, want %q", gotUser, fmt.Sprintf("user-%d", i))
			}
			if string(gotState) != id {
				t.Errorf("state = %q, want %q", gotState, id)
			}
		}
	})
}
