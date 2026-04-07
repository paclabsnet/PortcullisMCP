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

package identity

import (
	"strings"
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

func TestFilterClaims(t *testing.T) {
	t.Parallel()

	base := map[string]any{
		"sub":    "alice",
		"email":  "alice@corp.com",
		"ssn":    "123-45-6789",
		"groups": []any{"admins"},
	}

	tests := []struct {
		name      string
		allow     []string
		deny      []string
		wantKeys  []string
		noKeys    []string
	}{
		{
			name:     "no filters passes all keys",
			allow:    nil,
			deny:     nil,
			wantKeys: []string{"sub", "email", "ssn", "groups"},
		},
		{
			name:     "allowlist restricts to listed keys",
			allow:    []string{"sub", "email"},
			deny:     nil,
			wantKeys: []string{"sub", "email"},
			noKeys:   []string{"ssn", "groups"},
		},
		{
			name:     "denylist removes listed keys",
			allow:    nil,
			deny:     []string{"ssn"},
			wantKeys: []string{"sub", "email", "groups"},
			noKeys:   []string{"ssn"},
		},
		{
			name:     "deny takes precedence over allow",
			allow:    []string{"sub", "ssn"},
			deny:     []string{"ssn"},
			wantKeys: []string{"sub"},
			noKeys:   []string{"ssn", "email", "groups"},
		},
		{
			name:     "empty source map returns empty result",
			allow:    nil,
			deny:     nil,
			wantKeys: nil,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := base
			if tc.name == "empty source map returns empty result" {
				src = map[string]any{}
			}
			got := FilterClaims(src, tc.allow, tc.deny)
			for _, k := range tc.wantKeys {
				if _, ok := got[k]; !ok {
					t.Errorf("expected key %q in filtered result, but it was absent", k)
				}
			}
			for _, k := range tc.noKeys {
				if _, ok := got[k]; ok {
					t.Errorf("key %q should have been filtered out, but it was present", k)
				}
			}
		})
	}
}

func TestFilterClaims_DoesNotMutateSource(t *testing.T) {
	t.Parallel()
	src := map[string]any{"sub": "alice", "ssn": "secret"}
	_ = FilterClaims(src, nil, []string{"ssn"})
	if _, ok := src["ssn"]; !ok {
		t.Error("FilterClaims must not mutate the source map")
	}
}

func TestValidatePrincipal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		principal   shared.Principal
		cfg         NormalizerConfig
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid principal passes",
			principal: shared.Principal{UserID: "alice"},
			cfg:       NormalizerConfig{},
			wantErr:   false,
		},
		{
			name:        "missing user_id is rejected",
			principal:   shared.Principal{UserID: ""},
			cfg:         NormalizerConfig{},
			wantErr:     true,
			errContains: "missing user_id",
		},
		{
			name:        "user_id exceeding max length is rejected",
			principal:   shared.Principal{UserID: strings.Repeat("a", 257)},
			cfg:         NormalizerConfig{MaxUserIDLength: 256},
			wantErr:     true,
			errContains: "user_id exceeds maximum length",
		},
		{
			name:      "user_id at exact max length is accepted",
			principal: shared.Principal{UserID: strings.Repeat("a", 256)},
			cfg:       NormalizerConfig{MaxUserIDLength: 256},
			wantErr:   false,
		},
		{
			name:      "max_userid_length zero means no limit",
			principal: shared.Principal{UserID: strings.Repeat("a", 1000)},
			cfg:       NormalizerConfig{MaxUserIDLength: 0},
			wantErr:   false,
		},
		{
			name:        "too many groups is rejected",
			principal:   shared.Principal{UserID: "alice", Groups: []string{"a", "b", "c"}},
			cfg:         NormalizerConfig{MaxGroupsCount: 2},
			wantErr:     true,
			errContains: "groups count 3 exceeds maximum of 2",
		},
		{
			name:      "groups at exact max count is accepted",
			principal: shared.Principal{UserID: "alice", Groups: []string{"a", "b"}},
			cfg:       NormalizerConfig{MaxGroupsCount: 2},
			wantErr:   false,
		},
		{
			name:        "group name exceeding max length is rejected",
			principal:   shared.Principal{UserID: "alice", Groups: []string{strings.Repeat("g", 129)}},
			cfg:         NormalizerConfig{MaxGroupNameLength: 128},
			wantErr:     true,
			errContains: "exceeds maximum length of 128",
		},
		{
			name:      "group name at exact max length is accepted",
			principal: shared.Principal{UserID: "alice", Groups: []string{strings.Repeat("g", 128)}},
			cfg:       NormalizerConfig{MaxGroupNameLength: 128},
			wantErr:   false,
		},
		{
			name:      "max_groups_count zero means no limit",
			principal: shared.Principal{UserID: "alice", Groups: make([]string, 500)},
			cfg:       NormalizerConfig{MaxGroupsCount: 0},
			wantErr:   false,
		},
		{
			name:      "empty groups slice skips group checks",
			principal: shared.Principal{UserID: "alice", Groups: nil},
			cfg:       NormalizerConfig{MaxGroupsCount: 1, MaxGroupNameLength: 1},
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePrincipal(tc.principal, tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error = %q, want substring %q", err.Error(), tc.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
