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

import "fmt"

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
