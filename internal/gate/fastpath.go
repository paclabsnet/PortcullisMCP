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

// FastPath evaluates a tool call locally without a network round-trip.
// It only makes decisions for filesystem operations; all other calls return
// FastPathForward.
//
// Rules (evaluated in order):
//  1. Any resolved path that matches a protected path → deny immediately.
//  2. All resolved paths entirely within the sandbox directory → allow immediately.
//  3. Everything else → forward to Keep.
//
// Both rules resolve symlinks and clean the path before comparison to prevent
// path traversal and symlink attacks.
//
// Multi-path tools (copy_file, move_file) extract all path arguments; all
// paths must pass both rules for an allow decision.
func (g *Gate) FastPath(_ context.Context, toolName string, args map[string]any) (FastPathResult, error) {
	paths := extractPaths(args)
	if len(paths) == 0 {
		// Not a filesystem operation we recognise; forward to Keep.
		return FastPathForward, nil
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

	// Rule 1: protected paths take priority over the sandbox.
	for _, r := range resolved {
		for _, p := range g.cfg.ProtectedPaths {
			protected, err := resolvePath(p)
			if err != nil {
				continue
			}
			if isContainedIn(r, protected) {
				return FastPathDeny, nil
			}
		}
	}

	// Rule 2: all paths must be within the sandbox for a local allow.
	if g.cfg.Sandbox.Directory != "" {
		sandbox, err := resolvePath(g.cfg.Sandbox.Directory)
		if err == nil {
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
	}

	return FastPathForward, nil
}

// extractPaths returns all filesystem path arguments from a tool call's
// argument map. It handles three argument conventions:
//   - "path": single path (most tools)
//   - "source" + "destination": two-path tools (copy_file, move_file)
//   - "paths": slice of paths (read_multiple_files)
//
// Returns nil if no recognised path arguments are found.
func extractPaths(args map[string]any) []string {
	var out []string

	if v, ok := args["path"]; ok {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
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
// For paths that do not yet exist (e.g. a write_file target), it resolves
// the parent directory and reconstructs the final component, so that new
// files inside the sandbox are correctly fast-pathed rather than denied.
func resolvePath(path string) (string, error) {
	clean := filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(clean)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	// Path does not exist yet. Resolve the parent and reconstruct.
	parent, base := filepath.Split(clean)
	resolvedParent, err := filepath.EvalSymlinks(strings.TrimSuffix(parent, string(filepath.Separator)))
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, base), nil
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

// isFastPathTool reports whether the tool name is a known filesystem tool
// that may be subject to fast-path evaluation. This is a defence-in-depth
// check; the path extraction in extractPath is the primary gate.
func isFastPathTool(toolName string) bool {
	switch toolName {
	case "read_text_file", "read_file", "read_media_file", "read_multiple_files",
		"write_file", "edit_file",
		"list_directory", "list_directory_with_sizes", "directory_tree",
		"create_directory", "move_file", "copy_file", "delete_file",
		"search_files", "search_within_files", "get_file_info",
		"list_allowed_directories":
		return true
	}
	return false
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
