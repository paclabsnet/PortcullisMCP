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
	"fmt"
	"net/http"
	"strings"
)

// ForbiddenHeaders is the hard-coded set of headers that must never be forwarded
// from clients to backend MCPs, regardless of operator configuration. It covers
// hop-by-hop headers (RFC 2616), protocol-integrity headers, and Portcullis
// internal tracing headers. Keys are in http.CanonicalHeaderKey form.
var ForbiddenHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true, // canonical form of TE
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Host":                true,
	"Content-Length":      true,
	"Expect":              true,
	"Content-Type":        true,
	"Traceparent":         true,
	"Tracestate":          true,
}

// IsForbiddenHeader reports whether name is a header that must never be forwarded.
// The check covers the hard-coded ForbiddenHeaders set and any header whose
// canonical name begins with "X-Portcullis-".
func IsForbiddenHeader(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	if ForbiddenHeaders[canonical] {
		return true
	}
	return strings.HasPrefix(strings.ToLower(canonical), "x-portcullis-")
}

// FieldCheck pairs a string value with a field name and its maximum allowed
// byte length. A Max of 0 means no limit is configured — the check is skipped.
type FieldCheck struct {
	Value string
	Name  string
	Max   int
}

// CheckFields runs byte-length validation on each entry in checks and returns
// the first error encountered, or nil if all pass.
// Entries with Max == 0 are silently skipped.
func CheckFields(checks []FieldCheck) error {
	for _, c := range checks {
		if err := CheckLen(c.Value, c.Name, c.Max); err != nil {
			return err
		}
	}
	return nil
}

// CheckLen returns an error if value exceeds max bytes, or nil if it does not.
// When max is 0 the check is skipped (no limit configured).
func CheckLen(value, fieldName string, max int) error {
	if max > 0 && len(value) > max {
		return fmt.Errorf("%s exceeds maximum length of %d bytes", fieldName, max)
	}
	return nil
}
