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
//  2. Any resolved path that is entirely within the sandbox directory → allow immediately.
//  3. Everything else → forward to Keep.
//
// Both rules resolve symlinks and clean the path before comparison to prevent
// path traversal and symlink attacks.
func (g *Gate) FastPath(_ context.Context, toolName string, args map[string]any) (FastPathResult, error) {
	path, ok := extractPath(args)
	if !ok {
		// Not a filesystem operation we recognise; forward to Keep.
		return FastPathForward, nil
	}

	resolved, err := resolvePath(path)
	if err != nil {
		// Cannot resolve the path — deny to be safe.
		return FastPathDeny, nil
	}

	// Rule 1: protected paths take priority over the sandbox.
	for _, p := range g.cfg.ProtectedPaths {
		protected, err := resolvePath(p)
		if err != nil {
			continue
		}
		if isContainedIn(resolved, protected) {
			return FastPathDeny, nil
		}
	}

	// Rule 2: sandbox allow.
	if g.cfg.Sandbox.Directory != "" {
		sandbox, err := resolvePath(g.cfg.Sandbox.Directory)
		if err == nil && isContainedIn(resolved, sandbox) {
			return FastPathAllow, nil
		}
	}

	return FastPathForward, nil
}

// extractPath returns the path argument from a tool call's argument map.
// MCP filesystem servers use "path" as the canonical argument name.
func extractPath(args map[string]any) (string, bool) {
	v, ok := args["path"]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok && s != ""
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
		"create_directory", "move_file", "search_files", "get_file_info",
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
	RequestID string
	Reason    string
}

// toSharedDeny converts a FastPathDeny decision into the shared sentinel error.
func (d FastPathDecision) Error() error {
	if d.Result == FastPathDeny {
		return shared.ErrDenied
	}
	return nil
}
