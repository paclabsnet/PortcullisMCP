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

import "testing"

func TestMatchesHeaderPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		header  string
		want    bool
	}{
		// Global wildcard
		{name: "wildcard matches any header", pattern: "*", header: "Authorization", want: true},
		{name: "wildcard matches custom header", pattern: "*", header: "X-Tenant-Id", want: true},
		{name: "wildcard matches empty string", pattern: "*", header: "", want: true},

		// Prefix (suffix-wildcard) matching
		{name: "prefix wildcard matches exact prefix", pattern: "x-tenant-*", header: "X-Tenant-Id", want: true},
		{name: "prefix wildcard matches longer header", pattern: "x-amzn-*", header: "X-Amzn-RequestId", want: true},
		{name: "prefix wildcard does not match different prefix", pattern: "x-tenant-*", header: "X-Other-Id", want: false},
		{name: "prefix wildcard is case-insensitive", pattern: "X-TENANT-*", header: "x-tenant-region", want: true},
		{name: "prefix wildcard does not match just the prefix", pattern: "x-tenant-*", header: "x-tenant-", want: true},
		{name: "prefix wildcard requires prefix chars", pattern: "x-tenant-*", header: "x-tenan", want: false},

		// Exact matching
		{name: "exact match succeeds", pattern: "Authorization", header: "Authorization", want: true},
		{name: "exact match is case-insensitive", pattern: "authorization", header: "Authorization", want: true},
		{name: "exact match fails on different header", pattern: "Authorization", header: "X-Auth-Token", want: false},
		{name: "exact match does not treat * mid-string as wildcard", pattern: "x-*-id", header: "x-foo-id", want: false},

		// Edge cases
		{name: "empty pattern does not match non-empty header", pattern: "", header: "Authorization", want: false},
		{name: "empty pattern matches empty header", pattern: "", header: "", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesHeaderPattern(tc.pattern, tc.header)
			if got != tc.want {
				t.Errorf("MatchesHeaderPattern(%q, %q) = %v, want %v", tc.pattern, tc.header, got, tc.want)
			}
		})
	}
}
