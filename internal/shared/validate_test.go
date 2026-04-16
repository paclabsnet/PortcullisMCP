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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsForbiddenHeader(t *testing.T) {
	tests := []struct {
		header   string
		expected bool
	}{
		{"Connection", true},
		{"connection", true},
		{"Content-Length", true},
		{"X-Portcullis-Trace", true},
		{"x-portcullis-auth", true},
		{"Authorization", false},
		{"Content-Encoding", false},
		{"X-Custom-Header", false},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsForbiddenHeader(tt.header))
		})
	}
}

func TestCheckLen(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		fieldName string
		max       int
		wantErr   bool
	}{
		{"under limit", "hello", "test", 10, false},
		{"at limit", "hello", "test", 5, false},
		{"over limit", "hello", "test", 4, true},
		{"no limit", "hello world", "test", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckLen(tt.value, tt.fieldName, tt.max)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.fieldName)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckFields(t *testing.T) {
	t.Run("all valid", func(t *testing.T) {
		checks := []FieldCheck{
			{"val1", "field1", 10},
			{"val2", "field2", 0},
		}
		assert.NoError(t, CheckFields(checks))
	})

	t.Run("one invalid", func(t *testing.T) {
		checks := []FieldCheck{
			{"val1", "field1", 10},
			{"too long", "field2", 5},
		}
		err := CheckFields(checks)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "field2")
	})
}
