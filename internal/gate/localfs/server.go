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

// Package localfs provides an in-process MCP filesystem server for
// portcullis-gate. It is connected via an in-memory transport (no subprocess,
// no stdio). It can operate on any path on the local filesystem; access control
// is enforced by portcullis-gate before any call reaches this server:
//   - Paths within the sandbox directory are allowed immediately (fast-path).
//   - All other paths require authorization from portcullis-keep before gate
//     calls this server.
//
// The tool set mirrors @modelcontextprotocol/server-filesystem so that agents
// trained against the official npm package see identical tool names, schemas,
// and response formats.
package localfs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// NewServer creates an MCP server that exposes filesystem tools for any path
// on the local filesystem. sandboxDirs lists the allowed sandbox directories;
// the first entry is used as the base for resolving relative paths. At least
// one directory must be provided. The caller is responsible for connecting a
// transport.
func NewServer(sandboxDirs []string) (*mcp.Server, error) {
	if len(sandboxDirs) == 0 {
		return nil, fmt.Errorf("localfs: at least one sandbox directory is required")
	}
	resolved := make([]string, 0, len(sandboxDirs))
	for _, d := range sandboxDirs {
		r, err := filepath.EvalSymlinks(filepath.Clean(d))
		if err != nil {
			return nil, fmt.Errorf("localfs: resolve sandbox dir %q: %w", d, err)
		}
		resolved = append(resolved, r)
	}

	s := &fsServer{sandbox: resolved[0], sandboxDirs: resolved}

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "portcullis-localfs",
		Version: "0.1.0",
	}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "read_text_file",
		Description: "Read the complete contents of a file from the file system as text. Handles various text encodings and provides detailed error messages if the file cannot be read. Use the 'head' parameter to read only the first N lines, or 'tail' for the last N lines. Access to paths outside the fast-path directory is policy-enforced by Portcullis and may require escalation approval.",
	}, s.readTextFile)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "read_media_file",
		Description: "Read an image or audio file from any path on the filesystem. Returns the base64 encoded data and MIME type. Access is policy-enforced by Portcullis.",
	}, s.readMediaFile)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "read_multiple_files",
		Description: "Read the contents of multiple files simultaneously. More efficient than reading files one by one. Each file's content is returned with its path as a reference. Failed reads for individual files won't stop the entire operation. Access is policy-enforced by Portcullis.",
	}, s.readMultipleFiles)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "write_file",
		Description: "Create a new file or completely overwrite an existing file with new content. Can write to any path on the filesystem. Access is policy-enforced by Portcullis — the operation will be denied or may require escalation approval depending on the path and enterprise policy.",
	}, s.writeFile)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "edit_file",
		Description: "Make line-based edits to a text file. Each edit replaces exact line sequences with new content. Returns a git-style diff showing the changes made. Can edit files at any path on the filesystem, subject to Portcullis policy enforcement.",
	}, s.editFile)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_directory",
		Description: "Create a new directory or ensure a directory exists. Can create multiple nested directories in one operation. Can create directories at any path on the filesystem, subject to Portcullis policy enforcement.",
	}, s.createDirectory)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_directory",
		Description: "Get a detailed listing of all files and directories in a specified path. Results distinguish between files and directories with [FILE] and [DIR] prefixes. Can list any directory on the filesystem, subject to Portcullis policy enforcement.",
	}, s.listDirectory)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_directory_with_sizes",
		Description: "Get a detailed listing of all files and directories in a specified path, including file sizes. Can list any directory on the filesystem, subject to Portcullis policy enforcement.",
	}, s.listDirectoryWithSizes)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "directory_tree",
		Description: "Get a recursive tree view of files and directories as a JSON structure. Each entry includes 'name', 'type' (file/directory), and 'children' for directories. Can traverse any directory on the filesystem, subject to Portcullis policy enforcement.",
	}, s.directoryTree)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "move_file",
		Description: "Move or rename files and directories. Can move files between any directories on the filesystem. If the destination exists, the operation will fail. Subject to Portcullis policy enforcement.",
	}, s.moveFile)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "search_files",
		Description: "Recursively search for files and directories matching a glob pattern. Use '*.ext' to match files in a directory, '**/*.ext' to match recursively. Returns full paths to all matching items. Can search any directory on the filesystem, subject to Portcullis policy enforcement.",
	}, s.searchFiles)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "copy_file",
		Description: "Create a copy of a file at a new location. If the destination exists, the operation will fail. Can copy files between any paths on the filesystem, subject to Portcullis policy enforcement.",
	}, s.copyFile)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "delete_file",
		Description: "Delete a file or directory. For directories, use the recursive flag to delete non-empty directories. Use with caution as this operation cannot be undone. Can delete files at any path on the filesystem, subject to Portcullis policy enforcement.",
	}, s.deleteFile)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "search_within_files",
		Description: "Search for text patterns within files. Recursively searches through text files for a given pattern, returning matches with file paths, line numbers, and matched content. Supports exclude patterns to skip certain files. Case-sensitive by default. Subject to Portcullis policy enforcement.",
	}, s.searchWithinFiles)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_file_info",
		Description: "Retrieve detailed metadata about a file or directory including size, creation time, last modified time, permissions, and type. Can retrieve info for any path on the filesystem, subject to Portcullis policy enforcement.",
	}, s.getFileInfo)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_allowed_directories",
		Description: "Returns information about filesystem access policy. All paths on the filesystem are accessible subject to Portcullis policy enforcement. Use this tool to understand which paths are in the fast-path (no policy check required) and which require policy evaluation.",
	}, s.listAllowedDirectories)

	return srv, nil
}

// Connect creates a connected in-memory client session to a new localfs server.
// This is the primary entry point for gate to obtain a local filesystem client.
// sandboxDirs must contain at least one directory; the first is used as the
// base for resolving relative paths.
func Connect(ctx context.Context, sandboxDirs []string) (*mcp.ClientSession, error) {
	srv, err := NewServer(sandboxDirs)
	if err != nil {
		return nil, err
	}

	t1, t2 := mcp.NewInMemoryTransports()

	if _, err := srv.Connect(ctx, t1, nil); err != nil {
		return nil, fmt.Errorf("localfs: connect server side: %w", err)
	}

	client := mcp.NewClient(&mcp.Implementation{
		Name:    shared.ServiceGate,
		Version: "0.1.0",
	}, nil)

	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		return nil, fmt.Errorf("localfs: connect client side: %w", err)
	}
	return session, nil
}

// fsServer holds the sandbox constraints and implements tool handlers.
type fsServer struct {
	sandbox     string   // primary sandbox dir; used for relative-path resolution
	sandboxDirs []string // all configured sandbox dirs; resolve checks against each
}

// resolve returns an absolute, symlink-free path for the given input,
// enforcing that the result lies within the sandbox directory.
// Relative paths are resolved relative to the sandbox directory.
//
// For paths that do not exist (e.g. write targets or new directories), it
// walks up the ancestor chain to find the deepest existing component, resolves
// symlinks there, and reconstructs the full path. This correctly handles
// deeply nested new paths like /some/dir/a/b/c where none of the intermediates
// exist yet.
func (s *fsServer) resolve(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(s.sandbox, path)
	}
	clean := filepath.Clean(path)

	current := clean
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			full := filepath.Join(append([]string{resolved}, missing...)...)
			for _, sandboxDir := range s.sandboxDirs {
				rel, relErr := filepath.Rel(sandboxDir, full)
				if relErr == nil && !strings.HasPrefix(rel, "..") {
					return full, nil
				}
			}
			return "", fmt.Errorf("path is outside the sandbox directory")
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("resolve path: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("resolve path: no existing ancestor found for %q", path)
		}
		missing = append([]string{filepath.Base(current)}, missing...)
		current = parent
	}
}

// --- result helpers ---

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func errResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		IsError: true,
	}
}

// --- input types ---

// readTextInput is kept for documentation; the handler uses map[string]any
// so the SDK does not mark head/tail as required.
// type readTextInput struct { Path string; Head int; Tail int }

type pathInput struct {
	Path string `json:"path"`
}

type pathsInput struct {
	Paths []string `json:"paths"`
}

type writeInput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type fileEdit struct {
	OldText string `json:"oldText"`
	NewText string `json:"newText"`
}

type editInput struct {
	Path   string     `json:"path"`
	Edits  []fileEdit `json:"edits"`
	DryRun bool       `json:"dryRun"`
}

type moveInput struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type listDirWithSizesInput struct {
	Path   string  `json:"path"`
	SortBy *string `json:"sortBy,omitempty"` // optional: "name" or "size"
}

type directoryTreeInput struct {
	Path            string    `json:"path"`
	ExcludePatterns *[]string `json:"excludePatterns,omitempty"` // optional glob patterns
}

type searchInput struct {
	Path            string    `json:"path"`
	Pattern         string    `json:"pattern"` // glob pattern
	ExcludePatterns *[]string `json:"excludePatterns,omitempty"`
}

type copyInput struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type deleteInput struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive,omitempty"` // for directories
}

type searchWithinFilesInput struct {
	Path            string    `json:"path"`
	Pattern         string    `json:"pattern"` // text pattern to search for
	ExcludePatterns *[]string `json:"excludePatterns,omitempty"`
	CaseSensitive   *bool     `json:"caseSensitive,omitempty"` // default: true
}

// --- helper functions ---

// jsonInt extracts an integer value from a map, returning 0 if not found or not numeric.
func jsonInt(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch val := v.(type) {
	case int:
		return int64(val)
	case int64:
		return val
	case float64:
		return int64(val)
	case json.Number:
		i, _ := val.Int64()
		return i
	default:
		return 0
	}
}

// jsonStringSlice extracts a []string from a map value that may be
// []interface{} (JSON array decoded by encoding/json).
func jsonStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, elem := range raw {
		if s, ok := elem.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// --- tool handlers ---

func (s *fsServer) readTextFile(_ context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, any, error) {
	path, _ := in["path"].(string)
	resolved, err := s.resolve(path)
	if err != nil {
		return errResult(err), nil, nil
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return errResult(err), nil, nil
	}
	text := string(data)
	head := int(jsonInt(in, "head"))
	tail := int(jsonInt(in, "tail"))
	if head > 0 || tail > 0 {
		lines := strings.Split(text, "\n")
		switch {
		case head > 0:
			if head < len(lines) {
				lines = lines[:head]
			}
		case tail > 0:
			if tail < len(lines) {
				lines = lines[len(lines)-tail:]
			}
		}
		text = strings.Join(lines, "\n")
	}
	return textResult(text), nil, nil
}

func (s *fsServer) readMediaFile(_ context.Context, _ *mcp.CallToolRequest, in pathInput) (*mcp.CallToolResult, any, error) {
	resolved, err := s.resolve(in.Path)
	if err != nil {
		return errResult(err), nil, nil
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return errResult(err), nil, nil
	}

	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(resolved), "."))
	mimeType, isImage := mediaMIMEType(ext)

	if isImage {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.ImageContent{Data: data, MIMEType: mimeType}},
		}, nil, nil
	}
	// Audio and fallback: return as a data URI so the agent can interpret it.
	encoded := base64.StdEncoding.EncodeToString(data)
	return textResult(fmt.Sprintf("data:%s;base64,%s", mimeType, encoded)), nil, nil
}

func mediaMIMEType(ext string) (mimeType string, isImage bool) {
	switch ext {
	case "png":
		return "image/png", true
	case "jpg", "jpeg":
		return "image/jpeg", true
	case "gif":
		return "image/gif", true
	case "webp":
		return "image/webp", true
	case "bmp":
		return "image/bmp", true
	case "svg":
		return "image/svg+xml", true
	case "mp3":
		return "audio/mpeg", false
	case "wav":
		return "audio/wav", false
	case "ogg":
		return "audio/ogg", false
	case "flac":
		return "audio/flac", false
	default:
		return "application/octet-stream", false
	}
}

func (s *fsServer) readMultipleFiles(_ context.Context, _ *mcp.CallToolRequest, in pathsInput) (*mcp.CallToolResult, any, error) {
	var sb strings.Builder
	for i, p := range in.Paths {
		if i > 0 {
			sb.WriteString("\n---\n")
		}
		resolved, err := s.resolve(p)
		if err != nil {
			fmt.Fprintf(&sb, "%s: Error - %s", p, err)
			continue
		}
		data, err := os.ReadFile(resolved)
		if err != nil {
			fmt.Fprintf(&sb, "%s: Error - %s", p, err)
			continue
		}
		fmt.Fprintf(&sb, "%s\n%s", p, string(data))
	}
	return textResult(sb.String()), nil, nil
}

func (s *fsServer) writeFile(_ context.Context, _ *mcp.CallToolRequest, in writeInput) (*mcp.CallToolResult, any, error) {
	resolved, err := s.resolve(in.Path)
	if err != nil {
		return errResult(err), nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0750); err != nil {
		return errResult(err), nil, nil
	}
	if err := os.WriteFile(resolved, []byte(in.Content), 0640); err != nil {
		return errResult(err), nil, nil
	}
	return textResult(fmt.Sprintf("Successfully wrote to %s", resolved)), nil, nil
}

func (s *fsServer) editFile(_ context.Context, _ *mcp.CallToolRequest, in editInput) (*mcp.CallToolResult, any, error) {
	resolved, err := s.resolve(in.Path)
	if err != nil {
		return errResult(err), nil, nil
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return errResult(err), nil, nil
	}

	original := string(data)
	modified := original
	var diffSections []string

	for i, edit := range in.Edits {
		if !strings.Contains(modified, edit.OldText) {
			return errResult(fmt.Errorf("edit %d: text not found: %q", i+1, edit.OldText)), nil, nil
		}
		diffSections = append(diffSections, buildEditDiff(edit.OldText, edit.NewText))
		modified = strings.Replace(modified, edit.OldText, edit.NewText, 1)
	}

	diff := fmt.Sprintf("--- %s\n+++ %s\n%s", in.Path, in.Path, strings.Join(diffSections, "\n"))

	if in.DryRun {
		return textResult(diff), nil, nil
	}
	if err := os.WriteFile(resolved, []byte(modified), 0640); err != nil {
		return errResult(err), nil, nil
	}
	return textResult(diff), nil, nil
}

// buildEditDiff produces a simple unified-style diff block for one edit.
func buildEditDiff(oldText, newText string) string {
	var sb strings.Builder
	sb.WriteString("@@ edit @@\n")
	for _, line := range strings.Split(oldText, "\n") {
		fmt.Fprintf(&sb, "-%s\n", line)
	}
	for _, line := range strings.Split(newText, "\n") {
		fmt.Fprintf(&sb, "+%s\n", line)
	}
	return sb.String()
}

func (s *fsServer) createDirectory(_ context.Context, _ *mcp.CallToolRequest, in pathInput) (*mcp.CallToolResult, any, error) {
	resolved, err := s.resolve(in.Path)
	if err != nil {
		return errResult(err), nil, nil
	}
	if err := os.MkdirAll(resolved, 0750); err != nil {
		return errResult(err), nil, nil
	}
	return textResult(fmt.Sprintf("Successfully created directory %s", resolved)), nil, nil
}

func (s *fsServer) listDirectory(_ context.Context, _ *mcp.CallToolRequest, in pathInput) (*mcp.CallToolResult, any, error) {
	resolved, err := s.resolve(in.Path)
	if err != nil {
		return errResult(err), nil, nil
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return errResult(err), nil, nil
	}
	lines := make([]string, len(entries))
	for i, e := range entries {
		if e.IsDir() {
			lines[i] = "[DIR] " + e.Name() + "/"
		} else {
			lines[i] = "[FILE] " + e.Name()
		}
	}
	return textResult(strings.Join(lines, "\n")), nil, nil
}

func (s *fsServer) listDirectoryWithSizes(_ context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, any, error) {
	path, _ := in["path"].(string)
	resolved, err := s.resolve(path)
	if err != nil {
		return errResult(err), nil, nil
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return errResult(err), nil, nil
	}

	sortBy := "name"
	if v, _ := in["sortBy"].(string); v != "" {
		sortBy = v
	}

	type entry struct {
		name  string
		isDir bool
		size  int64
	}
	items := make([]entry, 0, len(entries))
	var totalSize int64
	fileCount, dirCount := 0, 0

	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		sz := info.Size()
		items = append(items, entry{name: e.Name(), isDir: e.IsDir(), size: sz})
		if e.IsDir() {
			dirCount++
		} else {
			fileCount++
			totalSize += sz
		}
	}

	if sortBy == "size" {
		sort.Slice(items, func(i, j int) bool {
			return items[i].size > items[j].size
		})
	}

	var sb strings.Builder
	for _, it := range items {
		if it.isDir {
			fmt.Fprintf(&sb, "[DIR] %s/\n", it.name)
		} else {
			fmt.Fprintf(&sb, "[FILE] %s (%s)\n", it.name, humanSize(it.size))
		}
	}
	fmt.Fprintf(&sb, "Total: %d files, %d dirs, %s", fileCount, dirCount, humanSize(totalSize))
	return textResult(sb.String()), nil, nil
}

func humanSize(b int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/gb)
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/mb)
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/kb)
	default:
		return fmt.Sprintf("%d bytes", b)
	}
}

// treeEntry mirrors the JSON structure returned by directory_tree.
type treeEntry struct {
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	Children *[]*treeEntry `json:"children,omitempty"` // pointer so empty dirs serialize as []
}

func (s *fsServer) directoryTree(_ context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, any, error) {
	path, _ := in["path"].(string)
	resolved, err := s.resolve(path)
	if err != nil {
		return errResult(err), nil, nil
	}
	excludePatterns := jsonStringSlice(in, "excludePatterns")
	tree, err := s.buildTree(resolved, excludePatterns)
	if err != nil {
		return errResult(err), nil, nil
	}
	data, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		return errResult(err), nil, nil
	}
	return textResult(string(data)), nil, nil
}

func (s *fsServer) buildTree(dir string, excludePatterns []string) ([]*treeEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var result []*treeEntry
	for _, e := range entries {
		if isExcluded(e.Name(), excludePatterns) {
			continue
		}
		if e.IsDir() {
			children, err := s.buildTree(filepath.Join(dir, e.Name()), excludePatterns)
			if err != nil {
				children = []*treeEntry{} // skip unreadable dirs
			}
			result = append(result, &treeEntry{Name: e.Name(), Type: "directory", Children: &children})
		} else {
			result = append(result, &treeEntry{Name: e.Name(), Type: "file"})
		}
	}
	return result, nil
}

func (s *fsServer) moveFile(_ context.Context, _ *mcp.CallToolRequest, in moveInput) (*mcp.CallToolResult, any, error) {
	src, err := s.resolve(in.Source)
	if err != nil {
		return errResult(fmt.Errorf("source: %w", err)), nil, nil
	}
	dst, err := s.resolve(in.Destination)
	if err != nil {
		return errResult(fmt.Errorf("destination: %w", err)), nil, nil
	}
	if _, err := os.Stat(dst); err == nil {
		return errResult(fmt.Errorf("destination already exists: %s", dst)), nil, nil
	}
	if err := os.Rename(src, dst); err != nil {
		return errResult(err), nil, nil
	}
	return textResult(fmt.Sprintf("Successfully moved %s to %s", src, dst)), nil, nil
}

func (s *fsServer) searchFiles(_ context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, any, error) {
	path, _ := in["path"].(string)
	root, err := s.resolve(path)
	if err != nil {
		return errResult(err), nil, nil
	}
	pattern, _ := in["pattern"].(string)
	if pattern == "" {
		return errResult(fmt.Errorf("pattern is required")), nil, nil
	}

	excludePatterns := jsonStringSlice(in, "excludePatterns")

	recursive := strings.Contains(pattern, "**")
	basePattern := pattern
	if recursive {
		// Strip the **/ prefix so we can match the base name.
		basePattern = filepath.Base(strings.TrimPrefix(pattern, "**/"))
	}

	var matches []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if isExcluded(d.Name(), excludePatterns) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path == root {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		var matched bool
		if recursive {
			matched, _ = filepath.Match(basePattern, d.Name())
		} else {
			// Non-recursive: only match directly under root.
			if filepath.Dir(path) == root {
				matched, _ = filepath.Match(pattern, d.Name())
			}
		}
		if matched {
			matches = append(matches, rel)
		}
		return nil
	})
	if err != nil {
		return errResult(err), nil, nil
	}
	if len(matches) == 0 {
		return textResult("No matches found"), nil, nil
	}
	return textResult(strings.Join(matches, "\n")), nil, nil
}

func (s *fsServer) getFileInfo(_ context.Context, _ *mcp.CallToolRequest, in pathInput) (*mcp.CallToolResult, any, error) {
	resolved, err := s.resolve(in.Path)
	if err != nil {
		return errResult(err), nil, nil
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return errResult(err), nil, nil
	}
	kind := "file"
	if info.IsDir() {
		kind = "directory"
	}
	// Creation time is platform-specific; use ModTime as a safe fallback.
	created := fileCreationTime(info)
	text := strings.Join([]string{
		fmt.Sprintf("size: %d bytes", info.Size()),
		fmt.Sprintf("created: %s", created.UTC().Format(time.RFC3339)),
		fmt.Sprintf("modified: %s", info.ModTime().UTC().Format(time.RFC3339)),
		fmt.Sprintf("permissions: %s", info.Mode().String()),
		fmt.Sprintf("type: %s", kind),
	}, "\n")
	return textResult(text), nil, nil
}

func (s *fsServer) listAllowedDirectories(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	dirList := strings.Join(s.sandboxDirs, "\n  ")
	text := "All directories on this computer are accessible, subject to Portcullis policy enforcement.\n\n" +
		"Fast-path directories (no policy check required):\n  " + dirList + "\n\n" +
		"Operations outside the fast-path directories are sent to portcullis-keep for policy evaluation. " +
		"Access may require escalation approval depending on the path and operation."
	return textResult(text), nil, nil
}

func (s *fsServer) copyFile(_ context.Context, _ *mcp.CallToolRequest, in copyInput) (*mcp.CallToolResult, any, error) {
	src, err := s.resolve(in.Source)
	if err != nil {
		return errResult(fmt.Errorf("source: %w", err)), nil, nil
	}
	dst, err := s.resolve(in.Destination)
	if err != nil {
		return errResult(fmt.Errorf("destination: %w", err)), nil, nil
	}

	// Check if source exists and is a file
	srcInfo, err := os.Stat(src)
	if err != nil {
		return errResult(fmt.Errorf("source: %w", err)), nil, nil
	}
	if srcInfo.IsDir() {
		return errResult(fmt.Errorf("source is a directory; only files can be copied")), nil, nil
	}

	// Check if destination already exists
	if _, err := os.Stat(dst); err == nil {
		return errResult(fmt.Errorf("destination already exists: %s", dst)), nil, nil
	}

	// Create destination directory if it doesn't exist
	dstDir := filepath.Dir(dst)
	if err := os.MkdirAll(dstDir, 0750); err != nil {
		return errResult(fmt.Errorf("create destination directory: %w", err)), nil, nil
	}

	// Open source before creating destination to avoid leaving an empty file
	// if the source is unreadable.
	srcFile, err := os.Open(src)
	if err != nil {
		return errResult(err), nil, nil
	}
	defer srcFile.Close()

	// Create destination with source permissions atomically (no world-readable
	// window between create and chmod).
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, srcInfo.Mode())
	if err != nil {
		return errResult(err), nil, nil
	}

	if _, err := dstFile.ReadFrom(srcFile); err != nil {
		dstFile.Close()
		os.Remove(dst) // clean up partial file
		return errResult(err), nil, nil
	}
	if err := dstFile.Close(); err != nil {
		os.Remove(dst)
		return errResult(err), nil, nil
	}

	return textResult(fmt.Sprintf("Successfully copied %s to %s", src, dst)), nil, nil
}

func (s *fsServer) deleteFile(_ context.Context, _ *mcp.CallToolRequest, in deleteInput) (*mcp.CallToolResult, any, error) {
	resolved, err := s.resolve(in.Path)
	if err != nil {
		return errResult(err), nil, nil
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return errResult(err), nil, nil
	}

	if info.IsDir() {
		if in.Recursive {
			if err := os.RemoveAll(resolved); err != nil {
				return errResult(err), nil, nil
			}
			return textResult(fmt.Sprintf("Successfully deleted directory %s and its contents", resolved)), nil, nil
		}
		// Try to remove empty directory
		if err := os.Remove(resolved); err != nil {
			return errResult(fmt.Errorf("directory not empty; use recursive=true to delete non-empty directories")), nil, nil
		}
		return textResult(fmt.Sprintf("Successfully deleted empty directory %s", resolved)), nil, nil
	}

	// Delete file
	if err := os.Remove(resolved); err != nil {
		return errResult(err), nil, nil
	}
	return textResult(fmt.Sprintf("Successfully deleted file %s", resolved)), nil, nil
}

func (s *fsServer) searchWithinFiles(_ context.Context, _ *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, any, error) {
	path, _ := in["path"].(string)
	root, err := s.resolve(path)
	if err != nil {
		return errResult(err), nil, nil
	}

	pattern, _ := in["pattern"].(string)
	if pattern == "" {
		return errResult(fmt.Errorf("pattern is required")), nil, nil
	}

	excludePatterns := jsonStringSlice(in, "excludePatterns")

	caseSensitive := true
	if v, ok := in["caseSensitive"].(bool); ok {
		caseSensitive = v
	}

	searchPattern := pattern
	if !caseSensitive {
		searchPattern = strings.ToLower(searchPattern)
	}

	type match struct {
		file string
		line int
		text string
	}
	var matches []match

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if isExcluded(d.Name(), excludePatterns) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}

		// Skip binary files (basic check by extension)
		ext := strings.ToLower(filepath.Ext(path))
		if isBinaryExt(ext) {
			return nil
		}

		// Read and search the file
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable files
		}

		// Skip if file appears to be binary
		if isBinary(data) {
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		lines := strings.Split(string(data), "\n")
		for lineNum, line := range lines {
			searchLine := line
			if !caseSensitive {
				searchLine = strings.ToLower(searchLine)
			}
			if strings.Contains(searchLine, searchPattern) {
				matches = append(matches, match{
					file: rel,
					line: lineNum + 1,
					text: strings.TrimSpace(line),
				})
			}
		}
		return nil
	})

	if err != nil {
		return errResult(err), nil, nil
	}

	if len(matches) == 0 {
		return textResult("No matches found"), nil, nil
	}

	// Format results
	var sb strings.Builder
	for _, m := range matches {
		fmt.Fprintf(&sb, "%s:%d: %s\n", m.file, m.line, m.text)
	}
	return textResult(strings.TrimSuffix(sb.String(), "\n")), nil, nil
}

// isBinaryExt reports whether a file extension is commonly binary.
func isBinaryExt(ext string) bool {
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".dat": true, ".db": true, ".sqlite": true,
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
		".bmp": true, ".ico": true, ".webp": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
		".pdf": true, ".zip": true, ".tar": true, ".gz": true,
		".7z": true, ".rar": true, ".class": true, ".pyc": true,
	}
	return binaryExts[ext]
}

// isBinary performs a simple heuristic check for binary data.
func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Check first 512 bytes for null bytes (common in binary files)
	checkLen := len(data)
	if checkLen > 512 {
		checkLen = 512
	}
	for i := 0; i < checkLen; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

// isExcluded reports whether a name matches any of the given glob patterns.
func isExcluded(name string, patterns []string) bool {
	for _, p := range patterns {
		if matched, _ := filepath.Match(p, name); matched {
			return true
		}
	}
	return false
}
