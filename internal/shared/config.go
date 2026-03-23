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
	"os"
	"regexp"
	"strings"
)

// ExpandEnvVars expands environment variable references in a string.
// Supports both ${VAR} and $VAR syntax.
func ExpandEnvVars(s string) string {
	return os.Expand(s, func(key string) string {
		return os.Getenv(key)
	})
}

// ExpandEnvVarsInMap recursively expands environment variables in all string
// values within a map.
func ExpandEnvVarsInMap(m map[string]string) map[string]string {
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = ExpandEnvVars(v)
	}
	return result
}

// ExpandEnvVarsInYAML performs environment variable expansion on YAML content
// before it is unmarshaled. This allows env vars anywhere in the config.
func ExpandEnvVarsInYAML(data []byte) []byte {
	// Pattern matches ${VAR} or $VAR
	pattern := regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}|\$([A-Za-z0-9_]+)`)
	return pattern.ReplaceAllFunc(data, func(match []byte) []byte {
		s := string(match)
		// Extract variable name
		varName := strings.TrimPrefix(s, "$")
		varName = strings.TrimPrefix(varName, "{")
		varName = strings.TrimSuffix(varName, "}")

		// Get value from environment
		if val := os.Getenv(varName); val != "" {
			return []byte(val)
		}
		// Return original if not found
		return match
	})
}
