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
