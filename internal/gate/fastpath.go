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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// FastPathResult is the outcome of a local fast-path evaluation.
type FastPathResult int

const (
	FastPathAllow   FastPathResult = iota // allow immediately; do not forward to Keep
	FastPathDeny                          // deny immediately; do not forward to Keep
	FastPathForward                       // no local decision; forward to Keep
)

// toolCategory maps each portcullis-localfs tool name to its operation category.
var toolCategory = map[string]string{
	"read_text_file":            "read",
	"read_media_file":           "read",
	"read_multiple_files":       "read",
	"list_directory":            "read",
	"list_directory_with_sizes": "read",
	"directory_tree":            "read",
	"search_files":              "read",
	"search_within_files":       "read",
	"get_file_info":             "read",
	"list_allowed_directories":  "read",
	"write_file":                "write",
	"create_directory":          "write",
	"move_file":                 "write",
	"copy_file":                 "write",
	"edit_file":                 "update",
	"delete_file":               "delete",
}

// effectiveStrategy returns the resolved strategy for the given tool name.
// Priority: tool-specific override > category default > "allow".
func effectiveStrategy(s LocalFSStrategyConfig, toolName string) string {
	// Tool-specific override takes precedence.
	override := toolStrategyOverride(s, toolName)
	if override != "" {
		return override
	}
	// Fall back to category-level default.
	switch toolCategory[toolName] {
	case "read":
		if s.Read != "" {
			return s.Read
		}
	case "write":
		if s.Write != "" {
			return s.Write
		}
	case "update":
		if s.Update != "" {
			return s.Update
		}
	case "delete":
		if s.Delete != "" {
			return s.Delete
		}
	}
	return "allow"
}

// toolStrategyOverride returns the tool-specific strategy override, or "" if none is set.
func toolStrategyOverride(s LocalFSStrategyConfig, toolName string) string {
	switch toolName {
	case "read_text_file":
		return s.ReadTextFile
	case "read_media_file":
		return s.ReadMediaFile
	case "read_multiple_files":
		return s.ReadMultipleFiles
	case "write_file":
		return s.WriteFile
	case "edit_file":
		return s.EditFile
	case "create_directory":
		return s.CreateDirectory
	case "list_directory":
		return s.ListDirectory
	case "list_directory_with_sizes":
		return s.ListDirectoryWithSizes
	case "directory_tree":
		return s.DirectoryTree
	case "move_file":
		return s.MoveFile
	case "search_files":
		return s.SearchFiles
	case "copy_file":
		return s.CopyFile
	case "delete_file":
		return s.DeleteFile
	case "search_within_files":
		return s.SearchWithinFiles
	case "get_file_info":
		return s.GetFileInfo
	case "list_allowed_directories":
		return s.ListAllowedDirectories
	}
	return ""
}

// FastPath evaluates a tool call locally without a network round-trip.
// It only makes decisions for filesystem operations; all other calls return
// FastPathForward.
//
// Evaluation order:
//  1. Path extraction — extract all path arguments and resolve to absolute,
//     symlink-free paths. Deny immediately if any path cannot be resolved.
//  2. Forbidden check — if any resolved path is within a forbidden directory,
//     deny immediately (takes precedence over all strategy settings).
//  3. Strategy resolution — determine the effective strategy for the tool
//     (tool-specific override > category default > "allow").
//  4. Strategy application:
//     - "deny"  → deny immediately (global).
//     - "verify" → forward to Keep (global).
//     - "allow" → allow if all paths are within a workspace directory (or
//     workspace contains "*"); otherwise forward to Keep.
func (g *Gate) FastPath(_ context.Context, toolName string, args map[string]any) (FastPathResult, error) {
	paths := extractPaths(args)
	if len(paths) == 0 {
		// Not a filesystem operation we recognise; forward to Keep.
		return FastPathForward, nil
	}

	// Snapshot the runtime policy. A nil policy means the tool is degraded
	// (source: keep, no valid policy fetched yet). Deny fail-closed.
	policy := g.getLocalFSPolicy()
	if policy == nil {
		return FastPathDeny, nil
	}

	var resolved []string
	for _, p := range paths {
		r, err := resolvePath(p)
		if err != nil {
			// Cannot resolve a path — deny to be safe.
			return FastPathDeny, nil
		}
		resolved = append(resolved, r)
	}

	// Step 2: Forbidden check — always evaluated first, always global.
	for _, r := range resolved {
		for _, p := range policy.Forbidden.Directories {
			forbidden, err := resolvePath(p)
			if err != nil {
				continue
			}
			if isContainedIn(r, forbidden) {
				return FastPathDeny, nil
			}
		}
	}

	// Step 3: Resolve the effective strategy for this tool.
	strategy := effectiveStrategy(policy.Strategy, toolName)

	// Step 4: Apply strategy.
	switch strategy {
	case "deny":
		return FastPathDeny, nil
	case "verify":
		return FastPathForward, nil
	default: // "allow"
		// All paths must be within a single workspace directory (or workspace
		// contains the "*" wildcard, which matches every path on the machine).
		for _, dir := range policy.Workspace.EffectiveDirs() {
			if dir == "*" {
				// Wildcard: all paths pass the workspace check.
				return FastPathAllow, nil
			}
			sandbox, err := resolvePath(dir)
			if err != nil {
				continue
			}
			allInSandbox := true
			for _, r := range resolved {
				if !isContainedIn(r, sandbox) {
					allInSandbox = false
					break
				}
			}
			if allInSandbox {
				return FastPathAllow, nil
			}
		}
		// No workspace matched — forward to Keep (implicit verify).
		return FastPathForward, nil
	}
}

// extractPaths returns all filesystem path arguments from a tool call's
// argument map. It handles four argument conventions:
//   - "path": single path (most tools)
//   - "directory": single path (used by some MCP filesystem clients)
//   - "source" + "destination": two-path tools (copy_file, move_file)
//   - "paths": slice of paths (read_multiple_files)
//
// Returns nil if no recognised path arguments are found.
func extractPaths(args map[string]any) []string {
	var out []string

	for _, key := range []string{"path", "directory"} {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}

	if v, ok := args["source"]; ok {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	if v, ok := args["destination"]; ok {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}

	if v, ok := args["paths"]; ok {
		if slice, ok := v.([]any); ok {
			for _, elem := range slice {
				if s, ok := elem.(string); ok && s != "" {
					out = append(out, s)
				}
			}
		}
	}

	return out
}

// resolvePath cleans and evaluates symlinks on the given path.
// It returns the absolute, symlink-free path.
// For paths that do not yet exist (e.g. a write_file target), it walks up the
// ancestor chain to find the deepest existing component, resolves symlinks
// there, and reconstructs the full path. This correctly handles arbitrarily
// deep new paths like /sandbox/a/b/c/file.txt where none of the intermediates
// exist yet.
func resolvePath(path string) (string, error) {
	clean := filepath.Clean(path)

	current := clean
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			return filepath.Join(append([]string{resolved}, missing...)...), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("resolvePath: no existing ancestor found for %q", path)
		}
		missing = append([]string{filepath.Base(current)}, missing...)
		current = parent
	}
}

// isContainedIn reports whether target is equal to or a subdirectory of base.
// Both paths must already be absolute and symlink-resolved.
func isContainedIn(target, base string) bool {
	// Ensure base ends with a separator so that /foo does not match /foobar.
	if !strings.HasSuffix(base, string(filepath.Separator)) {
		base += string(filepath.Separator)
	}
	return target == strings.TrimSuffix(base, string(filepath.Separator)) ||
		strings.HasPrefix(target, base)
}

// decisionLabel returns a log-friendly string for a FastPathResult.
func (r FastPathResult) String() string {
	switch r {
	case FastPathAllow:
		return "allow"
	case FastPathDeny:
		return "deny"
	default:
		return "forward"
	}
}

// FastPathDecision holds the result of a fast-path evaluation for logging.
type FastPathDecision struct {
	Result    FastPathResult
	ToolName  string
	Path      string
	SessionID string
	TraceID   string
	Reason    string
}

// toSharedDeny converts a FastPathDeny decision into the shared sentinel error.
func (d FastPathDecision) Error() error {
	if d.Result == FastPathDeny {
		return shared.ErrDenied
	}
	return nil
}
