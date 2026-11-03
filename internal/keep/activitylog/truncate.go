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

package activitylog

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// truncationEnvelope replaces an oversized payload in the activity log record.
type truncationEnvelope struct {
	Truncated bool   `json:"_truncated"`
	Bytes     int    `json:"_bytes"`
	Preview   string `json:"preview"`
}

// maybeTruncate returns the payload unchanged if its JSON serialisation is within
// maxBytes. If the serialised form exceeds maxBytes, it returns a truncationEnvelope
// containing the original byte count and a UTF-8-safe prefix preview.
func maybeTruncate(payload any, maxBytes int) any {
	if maxBytes <= 0 {
		return payload
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		// If we can't marshal, return as-is and let the outer marshal handle the error.
		return payload
	}
	if len(raw) <= maxBytes {
		return payload
	}
	// Clone the prefix so the returned string does not share the backing array
	// of raw (which may be several megabytes). Without this, retaining a 4 KB
	// preview keeps the entire serialised payload alive in memory.
	return truncationEnvelope{
		Truncated: true,
		Bytes:     len(raw),
		Preview:   strings.Clone(truncateUTF8(string(raw), maxBytes)),
	}
}

// truncateUTF8 returns a prefix of s that is at most maxBytes bytes long and
// ends on a valid UTF-8 rune boundary. If s fits within maxBytes it is returned
// unchanged.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Step back from the byte limit until we land on a valid rune boundary.
	// A UTF-8 continuation byte has the form 10xxxxxx (0x80–0xBF).
	// We step back at most 3 bytes (the maximum tail of a 4-byte rune).
	cut := maxBytes
	for cut > 0 && cut > maxBytes-4 {
		if utf8.RuneStart(s[cut]) {
			break
		}
		cut--
	}
	return s[:cut]
}
