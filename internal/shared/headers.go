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

import "strings"

// MatchesHeaderPattern reports whether header matches pattern using the
// Portcullis header-matching rules:
//
//   - "*" matches any header name.
//   - A pattern ending in "*" (e.g. "x-tenant-*") matches any header whose
//     lowercase name starts with the preceding string (prefix wildcard).
//   - All other patterns are compared case-insensitively against the header name.
//
// Both pattern and header are compared in lowercase; callers do not need to
// pre-normalise them.
func MatchesHeaderPattern(pattern, header string) bool {
	pattern = strings.ToLower(pattern)
	header = strings.ToLower(header)
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(header, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == header
}
