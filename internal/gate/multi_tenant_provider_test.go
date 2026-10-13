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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mtAuthReq(sid, token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if sid != "" {
		r.Header.Set("Mcp-Session-Id", sid)
	}
	r.Header.Set("X-User-Token", token)
	return r
}

// TestMultiTenantProvider_SessionIDPersistence verifies that the provider binds
// client-supplied session IDs to the credential fingerprint and keeps them stable.
func TestMultiTenantProvider_SessionIDPersistence(t *testing.T) {
	tests := []struct {
		name          string
		preSID        string // session pre-saved with preToken
		preToken      string
		reqSID        string
		reqToken      string
		wantSID       string // "" means any non-empty minted ID
		wantForbidden bool
	}{
		{name: "new session saved under supplied ID", reqSID: "sdk-1", reqToken: "tok-a", wantSID: "sdk-1"},
		{name: "same ID same token accepted", preSID: "sdk-2", preToken: "tok-a", reqSID: "sdk-2", reqToken: "tok-a", wantSID: "sdk-2"},
		{name: "same ID different token rejected", preSID: "sdk-3", preToken: "tok-a", reqSID: "sdk-3", reqToken: "tok-b", wantForbidden: true},
		{name: "no header mints ID", reqToken: "tok-a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemorySessionStore()
			ctx := context.Background()
			if tc.preSID != "" {
				if err := store.SaveSession(ctx, tc.preSID, "", credentialFingerprint(tc.preToken)); err != nil {
					t.Fatal(err)
				}
			}
			p := NewMultiTenantProvider("X-User-Token", store, nil)
			_, sid, err := p.Authenticate(mtAuthReq(tc.reqSID, tc.reqToken))
			if tc.wantForbidden {
				if err == nil || !strings.Contains(err.Error(), "forbidden") {
					t.Fatalf("err = %v, want forbidden", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sid == "" {
				t.Fatal("empty session ID")
			}
			if tc.wantSID != "" && sid != tc.wantSID {
				t.Errorf("sid = %q, want %q", sid, tc.wantSID)
			}
			if _, _, err := store.GetSession(ctx, sid); err != nil {
				t.Errorf("session %q not persisted: %v", sid, err)
			}
		})
	}

	t.Run("ID stable across two calls and enforced afterwards", func(t *testing.T) {
		p := NewMultiTenantProvider("X-User-Token", NewMemorySessionStore(), nil)
		_, s1, err := p.Authenticate(mtAuthReq("sdk-9", "tok-a"))
		if err != nil {
			t.Fatal(err)
		}
		_, s2, err := p.Authenticate(mtAuthReq("sdk-9", "tok-a"))
		if err != nil {
			t.Fatal(err)
		}
		if s1 != "sdk-9" || s2 != s1 {
			t.Errorf("IDs not stable: %q, %q", s1, s2)
		}
		if _, _, err := p.Authenticate(mtAuthReq("sdk-9", "tok-b")); err == nil || !strings.Contains(err.Error(), "forbidden") {
			t.Errorf("hijack attempt err = %v, want forbidden", err)
		}
	})
}

// TestMultiTenantProvider_BindRace verifies that when another request binds the
// ID between GetSession and the save, the loser is validated against the
// winner's fingerprint rather than overwriting it.
func TestMultiTenantProvider_BindRace(t *testing.T) {
	tests := []struct {
		name          string
		racerToken    string
		wantForbidden bool
	}{
		{"racer same credential accepted", "tok-a", false},
		{"racer different credential rejected", "tok-b", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mem := NewMemorySessionStore()
			store := &racingStore{MemorySessionStore: mem, onMiss: func() {
				_ = mem.SaveSession(context.Background(), "sdk-r", "", credentialFingerprint(tt.racerToken))
			}}
			p := NewMultiTenantProvider("X-User-Token", store, nil)
			_, _, err := p.Authenticate(mtAuthReq("sdk-r", "tok-a"))
			if tt.wantForbidden != (err != nil && strings.Contains(err.Error(), "forbidden")) {
				t.Errorf("err = %v, wantForbidden = %v", err, tt.wantForbidden)
			}
			st, _, _ := mem.GetSession(context.Background(), "sdk-r")
			if !bytes.Equal(st, credentialFingerprint(tt.racerToken)) {
				t.Error("racer's binding was overwritten")
			}
		})
	}
}

// racingStore simulates a concurrent bind landing right after a not-found Get.
type racingStore struct {
	*MemorySessionStore
	onMiss func()
	fired  bool
}

func (r *racingStore) GetSession(ctx context.Context, id string) ([]byte, string, error) {
	st, u, err := r.MemorySessionStore.GetSession(ctx, id)
	if err != nil && !r.fired {
		r.fired = true
		r.onMiss()
	}
	return st, u, err
}
