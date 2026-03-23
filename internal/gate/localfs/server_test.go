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

package localfs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// resultText extracts the text from the first TextContent in a CallToolResult.
func resultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("result has no content")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected *mcp.TextContent, got %T", result.Content[0])
	}
	return text.Text
}

func assertAllowed(t *testing.T, result *mcp.CallToolResult) {
	t.Helper()
	if result.IsError {
		t.Errorf("expected success, got error: %s", resultText(t, result))
	}
}

func assertDenied(t *testing.T, result *mcp.CallToolResult) {
	t.Helper()
	if !result.IsError {
		t.Errorf("expected error (denied), got success: %s", resultText(t, result))
	}
}

func setup(t *testing.T) (session *mcp.ClientSession, sandbox string, outside string) {
	t.Helper()
	sandbox = t.TempDir()
	outside = t.TempDir()
	ctx := context.Background()
	var err error
	session, err = Connect(ctx, sandbox)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return session, sandbox, outside
}

func call(t *testing.T, session *mcp.ClientSession, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      tool,
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool(%q): protocol error: %v", tool, err)
	}
	return result
}

func TestReadTextFile(t *testing.T) {
	session, sandbox, outside := setup(t)

	existing := filepath.Join(sandbox, "hello.txt")
	lines := "line1\nline2\nline3\nline4\nline5"
	if err := os.WriteFile(existing, []byte(lines), 0640); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		args    map[string]any
		want    string // substring expected in result
		denied  bool
	}{
		{
			name: "read full file",
			args: map[string]any{"path": existing},
			want: "line1",
		},
		{
			name: "head=2 returns first 2 lines",
			args: map[string]any{"path": existing, "head": 2},
			want: "line1\nline2",
		},
		{
			name: "tail=2 returns last 2 lines",
			args: map[string]any{"path": existing, "tail": 2},
			want: "line4\nline5",
		},
		{
			name:   "file outside sandbox denied",
			args:   map[string]any{"path": filepath.Join(outside, "x.txt")},
			denied: true,
		},
		{
			name:   "path traversal denied",
			args:   map[string]any{"path": filepath.Join(sandbox, "..", filepath.Base(outside), "x.txt")},
			denied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := call(t, session, "read_text_file", tt.args)
			if tt.denied {
				assertDenied(t, result)
			} else {
				assertAllowed(t, result)
				if tt.want != "" && !strings.Contains(resultText(t, result), tt.want) {
					t.Errorf("result %q does not contain %q", resultText(t, result), tt.want)
				}
			}
		})
	}
}

func TestReadTextFile_HeadTailEdgeCases(t *testing.T) {
	session, sandbox, _ := setup(t)
	f := filepath.Join(sandbox, "short.txt")
	if err := os.WriteFile(f, []byte("a\nb\nc"), 0640); err != nil {
		t.Fatal(err)
	}

	t.Run("head larger than file returns whole file", func(t *testing.T) {
		result := call(t, session, "read_text_file", map[string]any{"path": f, "head": 100})
		assertAllowed(t, result)
		if !strings.Contains(resultText(t, result), "a") {
			t.Error("expected file content")
		}
	})

	t.Run("tail larger than file returns whole file", func(t *testing.T) {
		result := call(t, session, "read_text_file", map[string]any{"path": f, "tail": 100})
		assertAllowed(t, result)
		if !strings.Contains(resultText(t, result), "c") {
			t.Error("expected file content")
		}
	})
}

func TestReadMultipleFiles(t *testing.T) {
	session, sandbox, outside := setup(t)

	f1 := filepath.Join(sandbox, "a.txt")
	f2 := filepath.Join(sandbox, "b.txt")
	if err := os.WriteFile(f1, []byte("aaa"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("bbb"), 0640); err != nil {
		t.Fatal(err)
	}

	t.Run("reads multiple allowed files", func(t *testing.T) {
		result := call(t, session, "read_multiple_files", map[string]any{"paths": []any{f1, f2}})
		assertAllowed(t, result)
		text := resultText(t, result)
		if !strings.Contains(text, "aaa") || !strings.Contains(text, "bbb") {
			t.Errorf("expected both file contents, got: %s", text)
		}
		if !strings.Contains(text, "\n---\n") {
			t.Error("expected files separated by \\n---\\n")
		}
	})

	t.Run("outside-sandbox file shows error inline, does not fail whole call", func(t *testing.T) {
		result := call(t, session, "read_multiple_files", map[string]any{"paths": []any{f1, filepath.Join(outside, "x.txt")}})
		assertAllowed(t, result) // overall call succeeds
		text := resultText(t, result)
		if !strings.Contains(text, "Error") {
			t.Errorf("expected inline error for denied file, got: %s", text)
		}
	})
}

func TestWriteFile(t *testing.T) {
	session, sandbox, outside := setup(t)

	t.Run("writes new file in sandbox", func(t *testing.T) {
		target := filepath.Join(sandbox, "new.txt")
		result := call(t, session, "write_file", map[string]any{"path": target, "content": "hello"})
		assertAllowed(t, result)
		data, err := os.ReadFile(target)
		if err != nil || string(data) != "hello" {
			t.Errorf("file not written correctly: %v %q", err, data)
		}
		if !strings.HasPrefix(resultText(t, result), "Successfully wrote to") {
			t.Errorf("unexpected success message: %s", resultText(t, result))
		}
	})

	t.Run("denied outside sandbox", func(t *testing.T) {
		result := call(t, session, "write_file", map[string]any{"path": filepath.Join(outside, "evil.txt"), "content": "x"})
		assertDenied(t, result)
		if _, err := os.Stat(filepath.Join(outside, "evil.txt")); !os.IsNotExist(err) {
			t.Error("file must not be written outside sandbox")
		}
	})
}

func TestEditFile(t *testing.T) {
	session, sandbox, outside := setup(t)

	f := filepath.Join(sandbox, "edit.txt")
	if err := os.WriteFile(f, []byte("hello world\nfoo bar\n"), 0640); err != nil {
		t.Fatal(err)
	}

	t.Run("applies edit and returns diff", func(t *testing.T) {
		result := call(t, session, "edit_file", map[string]any{
			"path":   f,
			"edits":  []any{map[string]any{"oldText": "hello world", "newText": "goodbye world"}},
			"dryRun": false,
		})
		assertAllowed(t, result)
		text := resultText(t, result)
		if !strings.Contains(text, "-hello world") || !strings.Contains(text, "+goodbye world") {
			t.Errorf("expected diff in result, got: %s", text)
		}
		data, _ := os.ReadFile(f)
		if !strings.Contains(string(data), "goodbye world") {
			t.Error("file should have been modified")
		}
	})

	t.Run("dry run does not modify file", func(t *testing.T) {
		before, _ := os.ReadFile(f)
		result := call(t, session, "edit_file", map[string]any{
			"path":   f,
			"edits":  []any{map[string]any{"oldText": "foo bar", "newText": "baz qux"}},
			"dryRun": true,
		})
		assertAllowed(t, result)
		after, _ := os.ReadFile(f)
		if string(before) != string(after) {
			t.Error("dry run must not modify the file")
		}
	})

	t.Run("error when oldText not found", func(t *testing.T) {
		result := call(t, session, "edit_file", map[string]any{
			"path":   f,
			"edits":  []any{map[string]any{"oldText": "does not exist", "newText": "x"}},
			"dryRun": false,
		})
		assertDenied(t, result)
	})

	t.Run("denied outside sandbox", func(t *testing.T) {
		result := call(t, session, "edit_file", map[string]any{
			"path":   filepath.Join(outside, "x.txt"),
			"edits":  []any{map[string]any{"oldText": "a", "newText": "b"}},
			"dryRun": false,
		})
		assertDenied(t, result)
	})
}

func TestListDirectory(t *testing.T) {
	session, sandbox, outside := setup(t)

	if err := os.WriteFile(filepath.Join(sandbox, "file.txt"), []byte("x"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sandbox, "subdir"), 0750); err != nil {
		t.Fatal(err)
	}

	t.Run("lists sandbox with [FILE] and [DIR] prefixes", func(t *testing.T) {
		result := call(t, session, "list_directory", map[string]any{"path": sandbox})
		assertAllowed(t, result)
		text := resultText(t, result)
		if !strings.Contains(text, "[FILE] file.txt") {
			t.Errorf("expected [FILE] file.txt, got: %s", text)
		}
		if !strings.Contains(text, "[DIR] subdir/") {
			t.Errorf("expected [DIR] subdir/, got: %s", text)
		}
	})

	t.Run("denied outside sandbox", func(t *testing.T) {
		assertDenied(t, call(t, session, "list_directory", map[string]any{"path": outside}))
	})
}

func TestListDirectoryWithSizes(t *testing.T) {
	session, sandbox, outside := setup(t)

	if err := os.WriteFile(filepath.Join(sandbox, "a.txt"), []byte("hello"), 0640); err != nil {
		t.Fatal(err)
	}

	t.Run("lists with sizes and total", func(t *testing.T) {
		result := call(t, session, "list_directory_with_sizes", map[string]any{"path": sandbox})
		assertAllowed(t, result)
		text := resultText(t, result)
		if !strings.Contains(text, "[FILE] a.txt") {
			t.Errorf("expected file entry, got: %s", text)
		}
		if !strings.Contains(text, "Total:") {
			t.Errorf("expected Total: line, got: %s", text)
		}
	})

	t.Run("denied outside sandbox", func(t *testing.T) {
		assertDenied(t, call(t, session, "list_directory_with_sizes", map[string]any{"path": outside}))
	})
}

func TestDirectoryTree(t *testing.T) {
	session, sandbox, outside := setup(t)

	if err := os.MkdirAll(filepath.Join(sandbox, "sub"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandbox, "sub", "leaf.txt"), []byte("x"), 0640); err != nil {
		t.Fatal(err)
	}

	t.Run("returns valid JSON tree", func(t *testing.T) {
		result := call(t, session, "directory_tree", map[string]any{"path": sandbox})
		assertAllowed(t, result)
		var tree []*treeEntry
		if err := json.Unmarshal([]byte(resultText(t, result)), &tree); err != nil {
			t.Fatalf("result is not valid JSON: %v", err)
		}
		if len(tree) == 0 {
			t.Fatal("expected at least one tree entry")
		}
		// sub directory should have children slice (even if empty)
		var sub *treeEntry
		for _, e := range tree {
			if e.Name == "sub" {
				sub = e
			}
		}
		if sub == nil {
			t.Fatal("expected 'sub' directory in tree")
		}
		if sub.Children == nil {
			t.Error("directory entry must have non-nil children")
		}
	})

	t.Run("excludePatterns omits matched entries", func(t *testing.T) {
		result := call(t, session, "directory_tree", map[string]any{
			"path":            sandbox,
			"excludePatterns": []any{"sub"},
		})
		assertAllowed(t, result)
		if strings.Contains(resultText(t, result), "sub") {
			t.Error("excluded pattern should not appear in tree")
		}
	})

	t.Run("denied outside sandbox", func(t *testing.T) {
		assertDenied(t, call(t, session, "directory_tree", map[string]any{"path": outside}))
	})
}

func TestCreateDirectory(t *testing.T) {
	session, sandbox, outside := setup(t)

	t.Run("creates nested directory in sandbox", func(t *testing.T) {
		dir := filepath.Join(sandbox, "a", "b", "c")
		result := call(t, session, "create_directory", map[string]any{"path": dir})
		assertAllowed(t, result)
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("directory not created: %v", err)
		}
		if !strings.HasPrefix(resultText(t, result), "Successfully created directory") {
			t.Errorf("unexpected message: %s", resultText(t, result))
		}
	})

	t.Run("denied outside sandbox", func(t *testing.T) {
		assertDenied(t, call(t, session, "create_directory", map[string]any{"path": filepath.Join(outside, "evil")}))
	})
}

func TestMoveFile(t *testing.T) {
	session, sandbox, outside := setup(t)

	t.Run("moves file within sandbox", func(t *testing.T) {
		src := filepath.Join(sandbox, "src.txt")
		dst := filepath.Join(sandbox, "dst.txt")
		if err := os.WriteFile(src, []byte("x"), 0640); err != nil {
			t.Fatal(err)
		}
		result := call(t, session, "move_file", map[string]any{"source": src, "destination": dst})
		assertAllowed(t, result)
		if _, err := os.Stat(dst); err != nil {
			t.Error("destination file should exist")
		}
		if _, err := os.Stat(src); !os.IsNotExist(err) {
			t.Error("source file should be gone")
		}
		if !strings.HasPrefix(resultText(t, result), "Successfully moved") {
			t.Errorf("unexpected message: %s", resultText(t, result))
		}
	})

	t.Run("denied when destination is outside sandbox", func(t *testing.T) {
		src := filepath.Join(sandbox, "exfil.txt")
		if err := os.WriteFile(src, []byte("secret"), 0640); err != nil {
			t.Fatal(err)
		}
		result := call(t, session, "move_file", map[string]any{
			"source":      src,
			"destination": filepath.Join(outside, "stolen.txt"),
		})
		assertDenied(t, result)
		if _, err := os.Stat(filepath.Join(outside, "stolen.txt")); !os.IsNotExist(err) {
			t.Error("file must not have been moved outside sandbox")
		}
	})

	t.Run("fails when destination exists", func(t *testing.T) {
		src := filepath.Join(sandbox, "src2.txt")
		dst := filepath.Join(sandbox, "dst2.txt")
		if err := os.WriteFile(src, []byte("a"), 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte("b"), 0640); err != nil {
			t.Fatal(err)
		}
		assertDenied(t, call(t, session, "move_file", map[string]any{"source": src, "destination": dst}))
	})
}

func TestSearchFiles(t *testing.T) {
	session, sandbox, outside := setup(t)

	if err := os.WriteFile(filepath.Join(sandbox, "match.go"), []byte("x"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandbox, "skip.txt"), []byte("x"), 0640); err != nil {
		t.Fatal(err)
	}

	t.Run("finds matching files", func(t *testing.T) {
		result := call(t, session, "search_files", map[string]any{"path": sandbox, "pattern": "*.go"})
		assertAllowed(t, result)
		if !strings.Contains(resultText(t, result), "match.go") {
			t.Error("expected match.go in results")
		}
	})

	t.Run("excludePatterns omits matching entries", func(t *testing.T) {
		result := call(t, session, "search_files", map[string]any{
			"path":            sandbox,
			"pattern":         "*.go",
			"excludePatterns": []any{"match.go"},
		})
		assertAllowed(t, result)
		if strings.Contains(resultText(t, result), "match.go") {
			t.Error("excluded file should not appear in results")
		}
	})

	t.Run("returns no matches message when nothing found", func(t *testing.T) {
		result := call(t, session, "search_files", map[string]any{"path": sandbox, "pattern": "*.xyz"})
		assertAllowed(t, result)
		if !strings.Contains(resultText(t, result), "No matches found") {
			t.Errorf("expected no-matches message, got: %s", resultText(t, result))
		}
	})

	t.Run("denied outside sandbox", func(t *testing.T) {
		assertDenied(t, call(t, session, "search_files", map[string]any{"path": outside, "pattern": "*"}))
	})
}

func TestGetFileInfo(t *testing.T) {
	session, sandbox, outside := setup(t)

	f := filepath.Join(sandbox, "info.txt")
	if err := os.WriteFile(f, []byte("hello"), 0640); err != nil {
		t.Fatal(err)
	}

	t.Run("returns metadata for file in sandbox", func(t *testing.T) {
		result := call(t, session, "get_file_info", map[string]any{"path": f})
		assertAllowed(t, result)
		text := resultText(t, result)
		for _, field := range []string{"size:", "created:", "modified:", "permissions:", "type:"} {
			if !strings.Contains(text, field) {
				t.Errorf("expected field %q in info, got: %s", field, text)
			}
		}
	})

	t.Run("denied outside sandbox", func(t *testing.T) {
		assertDenied(t, call(t, session, "get_file_info", map[string]any{"path": filepath.Join(outside, "x.txt")}))
	})
}

func TestListAllowedDirectories(t *testing.T) {
	session, sandbox, _ := setup(t)
	result := call(t, session, "list_allowed_directories", map[string]any{})
	assertAllowed(t, result)
	text := resultText(t, result)
	// The sandbox path (or its resolved form) should appear.
	if !strings.Contains(text, filepath.Base(sandbox)) {
		t.Errorf("expected sandbox path in response, got: %s", text)
	}
}

func TestLocalFS_Symlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}

	parent := t.TempDir()
	sandbox := filepath.Join(parent, "sandbox")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(sandbox, 0750); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.MkdirAll(outside, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideFile, []byte("secret"), 0640); err != nil {
		t.Fatal(err)
	}

	session, err := Connect(context.Background(), sandbox)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	t.Run("symlink inside sandbox pointing outside is denied", func(t *testing.T) {
		link := filepath.Join(sandbox, "escape")
		if err := os.Symlink(outsideFile, link); err != nil {
			t.Skipf("could not create symlink: %v", err)
		}
		result := call(t, session, "read_text_file", map[string]any{"path": link})
		assertDenied(t, result)
	})
}

func TestCopyFile(t *testing.T) {
	session, sandbox, outside := setup(t)

	// Create a source file
	src := filepath.Join(sandbox, "source.txt")
	if err := os.WriteFile(src, []byte("copy me"), 0640); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		args   map[string]any
		denied bool
	}{
		{
			name: "copies file within sandbox",
			args: map[string]any{
				"source":      src,
				"destination": filepath.Join(sandbox, "dest.txt"),
			},
		},
		{
			name: "creates destination directory if needed",
			args: map[string]any{
				"source":      src,
				"destination": filepath.Join(sandbox, "subdir", "dest.txt"),
			},
		},
		{
			name: "fails when destination exists",
			args: map[string]any{
				"source":      src,
				"destination": src, // same file
			},
			denied: true,
		},
		{
			name: "denied when source is outside sandbox",
			args: map[string]any{
				"source":      filepath.Join(outside, "file.txt"),
				"destination": filepath.Join(sandbox, "dest.txt"),
			},
			denied: true,
		},
		{
			name: "denied when destination is outside sandbox",
			args: map[string]any{
				"source":      src,
				"destination": filepath.Join(outside, "dest.txt"),
			},
			denied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := call(t, session, "copy_file", tt.args)
			if tt.denied {
				assertDenied(t, result)
			} else {
				assertAllowed(t, result)
				// Verify the copy exists
				dst := tt.args["destination"].(string)
				data, err := os.ReadFile(dst)
				if err != nil {
					t.Errorf("destination file not created: %v", err)
				} else if string(data) != "copy me" {
					t.Errorf("destination content = %q, want %q", string(data), "copy me")
				}
			}
		})
	}
}

func TestDeleteFile(t *testing.T) {
	session, sandbox, outside := setup(t)

	tests := []struct {
		name   string
		setup  func() string // returns path to delete
		args   map[string]any
		denied bool
	}{
		{
			name: "deletes file in sandbox",
			setup: func() string {
				path := filepath.Join(sandbox, "delete-me.txt")
				os.WriteFile(path, []byte("bye"), 0640)
				return path
			},
			args: func() map[string]any {
				return map[string]any{"path": ""}
			}(),
		},
		{
			name: "deletes empty directory",
			setup: func() string {
				path := filepath.Join(sandbox, "empty-dir")
				os.MkdirAll(path, 0750)
				return path
			},
			args: func() map[string]any {
				return map[string]any{"path": ""}
			}(),
		},
		{
			name: "fails on non-empty directory without recursive",
			setup: func() string {
				path := filepath.Join(sandbox, "non-empty")
				os.MkdirAll(path, 0750)
				os.WriteFile(filepath.Join(path, "file.txt"), []byte("x"), 0640)
				return path
			},
			args: func() map[string]any {
				return map[string]any{"path": "", "recursive": false}
			}(),
			denied: true,
		},
		{
			name: "deletes non-empty directory with recursive",
			setup: func() string {
				path := filepath.Join(sandbox, "non-empty2")
				os.MkdirAll(filepath.Join(path, "subdir"), 0750)
				os.WriteFile(filepath.Join(path, "file.txt"), []byte("x"), 0640)
				os.WriteFile(filepath.Join(path, "subdir", "file2.txt"), []byte("y"), 0640)
				return path
			},
			args: func() map[string]any {
				return map[string]any{"path": "", "recursive": true}
			}(),
		},
		{
			name: "denied outside sandbox",
			setup: func() string {
				return filepath.Join(outside, "file.txt")
			},
			args: func() map[string]any {
				return map[string]any{"path": ""}
			}(),
			denied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()
			tt.args["path"] = path
			result := call(t, session, "delete_file", tt.args)
			if tt.denied {
				assertDenied(t, result)
			} else {
				assertAllowed(t, result)
				// Verify the file/dir is gone
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Errorf("path still exists after delete: %s", path)
				}
			}
		})
	}
}

func TestSearchWithinFiles(t *testing.T) {
	session, sandbox, outside := setup(t)

	// Create test files with content
	files := map[string]string{
		"README.md":      "# Project\nThis is a test project\nWith multiple lines",
		"src/main.go":    "package main\n\nfunc main() {\n\ttest()\n}",
		"src/helper.go":  "package main\n\nfunc test() {\n\tprintln(\"testing\")\n}",
		"docs/guide.txt": "User guide\nTesting features\nEnd of guide",
		"binary.bin":     "\x00\x01\x02\x03", // binary file
	}

	for path, content := range files {
		fullPath := filepath.Join(sandbox, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0640); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name    string
		args    map[string]any
		wantMin int    // minimum number of matches
		wantStr string // substring that should appear in results
		denied  bool
	}{
		{
			name: "finds matches in multiple files",
			args: map[string]any{
				"path":    sandbox,
				"pattern": "test",
			},
			wantMin: 3, // test appears in multiple files
			wantStr: "main.go",
		},
		{
			name: "case insensitive search",
			args: map[string]any{
				"path":          sandbox,
				"pattern":       "PROJECT",
				"caseSensitive": false,
			},
			wantMin: 1,
			wantStr: "README.md",
		},
		{
			name: "excludes patterns",
			args: map[string]any{
				"path":            sandbox,
				"pattern":         "test",
				"excludePatterns": []string{"*.go"},
			},
			wantMin: 1,
			wantStr: "README.md", // should find in README, not in .go files
		},
		{
			name: "no matches found",
			args: map[string]any{
				"path":    sandbox,
				"pattern": "nonexistent-pattern-xyz",
			},
			wantStr: "No matches found",
		},
		{
			name: "denied outside sandbox",
			args: map[string]any{
				"path":    outside,
				"pattern": "test",
			},
			denied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := call(t, session, "search_within_files", tt.args)
			if tt.denied {
				assertDenied(t, result)
				return
			}
			assertAllowed(t, result)
			text := resultText(t, result)

			if tt.wantStr != "" && !strings.Contains(text, tt.wantStr) {
				t.Errorf("result does not contain %q\nGot: %s", tt.wantStr, text)
			}

			if tt.wantMin > 0 {
				lines := strings.Split(text, "\n")
				if len(lines) < tt.wantMin {
					t.Errorf("expected at least %d matches, got %d\nResult: %s", tt.wantMin, len(lines), text)
				}
			}
		})
	}
}

func TestReadMediaFile(t *testing.T) {
	session, sandbox, outside := setup(t)

	// Minimal 1x1 white PNG (valid file, not just magic bytes).
	pngB64 := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwADhQGAWjR9awAAAABJRU5ErkJggg=="
	pngData, _ := base64.StdEncoding.DecodeString(pngB64)

	pngFile := filepath.Join(sandbox, "pixel.png")
	if err := os.WriteFile(pngFile, pngData, 0640); err != nil {
		t.Fatal(err)
	}

	// A tiny fake SVG (also an image type).
	svgFile := filepath.Join(sandbox, "icon.svg")
	if err := os.WriteFile(svgFile, []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), 0640); err != nil {
		t.Fatal(err)
	}

	// A fake MP3 (non-image media: returned as data URI).
	mp3File := filepath.Join(sandbox, "sound.mp3")
	if err := os.WriteFile(mp3File, []byte("ID3fake"), 0640); err != nil {
		t.Fatal(err)
	}

	t.Run("PNG returns ImageContent", func(t *testing.T) {
		result := call(t, session, "read_media_file", map[string]any{"path": pngFile})
		assertAllowed(t, result)
		if len(result.Content) == 0 {
			t.Fatal("expected content")
		}
		img, ok := result.Content[0].(*mcp.ImageContent)
		if !ok {
			t.Fatalf("expected *mcp.ImageContent for PNG, got %T", result.Content[0])
		}
		if img.MIMEType != "image/png" {
			t.Errorf("MIMEType = %q, want image/png", img.MIMEType)
		}
	})

	t.Run("SVG returns ImageContent", func(t *testing.T) {
		result := call(t, session, "read_media_file", map[string]any{"path": svgFile})
		assertAllowed(t, result)
		img, ok := result.Content[0].(*mcp.ImageContent)
		if !ok {
			t.Fatalf("expected *mcp.ImageContent for SVG, got %T", result.Content[0])
		}
		if img.MIMEType != "image/svg+xml" {
			t.Errorf("MIMEType = %q, want image/svg+xml", img.MIMEType)
		}
	})

	t.Run("MP3 returns data URI text", func(t *testing.T) {
		result := call(t, session, "read_media_file", map[string]any{"path": mp3File})
		assertAllowed(t, result)
		text := resultText(t, result)
		if !strings.HasPrefix(text, "data:audio/mpeg;base64,") {
			t.Errorf("expected data URI, got: %s", text)
		}
	})

	t.Run("denied outside sandbox", func(t *testing.T) {
		assertDenied(t, call(t, session, "read_media_file", map[string]any{
			"path": filepath.Join(outside, "img.png"),
		}))
	})
}

func TestListDirectoryWithSizes_SortBySize(t *testing.T) {
	session, sandbox, _ := setup(t)

	// Write two files with very different sizes.
	small := filepath.Join(sandbox, "small.txt")
	large := filepath.Join(sandbox, "large.txt")
	if err := os.WriteFile(small, []byte("hi"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(large, []byte(strings.Repeat("x", 10000)), 0640); err != nil {
		t.Fatal(err)
	}

	result := call(t, session, "list_directory_with_sizes", map[string]any{
		"path":   sandbox,
		"sortBy": "size",
	})
	assertAllowed(t, result)
	text := resultText(t, result)

	largeIdx := strings.Index(text, "large.txt")
	smallIdx := strings.Index(text, "small.txt")
	if largeIdx == -1 || smallIdx == -1 {
		t.Fatalf("expected both files in output, got: %s", text)
	}
	if largeIdx > smallIdx {
		t.Errorf("sortBy=size: large.txt should appear before small.txt\nGot:\n%s", text)
	}
}

func TestSearchFiles_Recursive(t *testing.T) {
	session, sandbox, _ := setup(t)

	// Create a nested structure.
	if err := os.MkdirAll(filepath.Join(sandbox, "a", "b"), 0750); err != nil {
		t.Fatal(err)
	}
	files := []string{
		filepath.Join(sandbox, "root.go"),
		filepath.Join(sandbox, "a", "mid.go"),
		filepath.Join(sandbox, "a", "b", "deep.go"),
		filepath.Join(sandbox, "a", "other.txt"),
	}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("x"), 0640); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("recursive **/*.go finds files at all depths", func(t *testing.T) {
		result := call(t, session, "search_files", map[string]any{
			"path":    sandbox,
			"pattern": "**/*.go",
		})
		assertAllowed(t, result)
		text := resultText(t, result)
		for _, want := range []string{"root.go", "mid.go", "deep.go"} {
			if !strings.Contains(text, want) {
				t.Errorf("expected %q in recursive results, got:\n%s", want, text)
			}
		}
		if strings.Contains(text, "other.txt") {
			t.Error("other.txt should not match *.go pattern")
		}
	})

	t.Run("non-recursive *.go finds only root-level files", func(t *testing.T) {
		result := call(t, session, "search_files", map[string]any{
			"path":    sandbox,
			"pattern": "*.go",
		})
		assertAllowed(t, result)
		text := resultText(t, result)
		if !strings.Contains(text, "root.go") {
			t.Errorf("expected root.go in results, got:\n%s", text)
		}
		if strings.Contains(text, "mid.go") || strings.Contains(text, "deep.go") {
			t.Errorf("non-recursive search should not return files in subdirs, got:\n%s", text)
		}
	})
}

func TestCopyFile_SourceIsDirectory(t *testing.T) {
	session, sandbox, _ := setup(t)

	dir := filepath.Join(sandbox, "mydir")
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	result := call(t, session, "copy_file", map[string]any{
		"source":      dir,
		"destination": filepath.Join(sandbox, "mydir-copy"),
	})
	assertDenied(t, result)
	if !strings.Contains(resultText(t, result), "directory") {
		t.Errorf("expected 'directory' in error message, got: %s", resultText(t, result))
	}
}

func TestWriteFile_CreatesIntermediateDirs(t *testing.T) {
	session, sandbox, _ := setup(t)

	target := filepath.Join(sandbox, "a", "b", "c", "new.txt")
	result := call(t, session, "write_file", map[string]any{"path": target, "content": "nested"})
	assertAllowed(t, result)
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "nested" {
		t.Errorf("file not written at nested path: %v %q", err, data)
	}
}

func TestGetFileInfo_Directory(t *testing.T) {
	session, sandbox, _ := setup(t)

	dir := filepath.Join(sandbox, "somedir")
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	result := call(t, session, "get_file_info", map[string]any{"path": dir})
	assertAllowed(t, result)
	text := resultText(t, result)
	if !strings.Contains(text, "type: directory") {
		t.Errorf("expected 'type: directory', got: %s", text)
	}
}

// --- unit tests for helper functions (same package, no round-trip needed) ---

func TestMediaMIMEType(t *testing.T) {
	tests := []struct {
		ext       string
		wantMIME  string
		wantImage bool
	}{
		{"png", "image/png", true},
		{"jpg", "image/jpeg", true},
		{"jpeg", "image/jpeg", true},
		{"gif", "image/gif", true},
		{"webp", "image/webp", true},
		{"bmp", "image/bmp", true},
		{"svg", "image/svg+xml", true},
		{"mp3", "audio/mpeg", false},
		{"wav", "audio/wav", false},
		{"ogg", "audio/ogg", false},
		{"flac", "audio/flac", false},
		{"xyz", "application/octet-stream", false}, // unknown → default
		{"", "application/octet-stream", false},
	}
	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			mime, isImage := mediaMIMEType(tt.ext)
			if mime != tt.wantMIME {
				t.Errorf("mediaMIMEType(%q) MIME = %q, want %q", tt.ext, mime, tt.wantMIME)
			}
			if isImage != tt.wantImage {
				t.Errorf("mediaMIMEType(%q) isImage = %v, want %v", tt.ext, isImage, tt.wantImage)
			}
		})
	}
}

func TestHumanSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 bytes"},
		{512, "512 bytes"},
		{1023, "1023 bytes"},
		{1024, "1.0 KB"},
		{2560, "2.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{int64(1.5 * 1024 * 1024), "1.5 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{int64(2.5 * 1024 * 1024 * 1024), "2.5 GB"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := humanSize(tt.bytes)
			if got != tt.want {
				t.Errorf("humanSize(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestIsBinary(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"plain text", []byte("hello world"), false},
		{"null byte at start", []byte{0x00, 0x01, 0x02}, true},
		{"null byte in middle", []byte("abc\x00def"), true},
		{"large text no nulls", []byte(strings.Repeat("a", 1024)), false},
		{"large with null past 512", append([]byte(strings.Repeat("a", 513)), 0x00), false},
		{"null byte within first 512 of large", append([]byte(strings.Repeat("a", 100)), append([]byte{0x00}, []byte(strings.Repeat("b", 900))...)...), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBinary(tt.data)
			if got != tt.want {
				t.Errorf("isBinary(%d bytes) = %v, want %v", len(tt.data), got, tt.want)
			}
		})
	}
}

func TestMoveFile_SourceOutsideSandbox(t *testing.T) {
	session, sandbox, outside := setup(t)

	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0640); err != nil {
		t.Fatal(err)
	}
	result := call(t, session, "move_file", map[string]any{
		"source":      outsideFile,
		"destination": filepath.Join(sandbox, "stolen.txt"),
	})
	assertDenied(t, result)
	if _, err := os.Stat(filepath.Join(sandbox, "stolen.txt")); !os.IsNotExist(err) {
		t.Error("file must not have been moved into sandbox")
	}
}

func TestListDirectoryWithSizes_ContainsDirectories(t *testing.T) {
	session, sandbox, _ := setup(t)

	if err := os.MkdirAll(filepath.Join(sandbox, "subdir"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandbox, "file.txt"), []byte("hello"), 0640); err != nil {
		t.Fatal(err)
	}

	result := call(t, session, "list_directory_with_sizes", map[string]any{"path": sandbox})
	assertAllowed(t, result)
	text := resultText(t, result)
	if !strings.Contains(text, "[DIR] subdir/") {
		t.Errorf("expected [DIR] subdir/ in output, got:\n%s", text)
	}
	if !strings.Contains(text, "[FILE] file.txt") {
		t.Errorf("expected [FILE] file.txt in output, got:\n%s", text)
	}
	// Dir count should be included in total.
	if !strings.Contains(text, "1 dirs") {
		t.Errorf("expected '1 dirs' in total line, got:\n%s", text)
	}
}

func TestSearchWithinFiles_BinaryContentSkipped(t *testing.T) {
	session, sandbox, _ := setup(t)

	// A .txt file containing null bytes — not caught by extension check,
	// so isBinary() must detect and skip it.
	binaryTxt := filepath.Join(sandbox, "looks-like-text.txt")
	if err := os.WriteFile(binaryTxt, []byte("some\x00binary\x00content"), 0640); err != nil {
		t.Fatal(err)
	}
	// A real text file that contains the same printable text without nulls.
	realTxt := filepath.Join(sandbox, "real.txt")
	if err := os.WriteFile(realTxt, []byte("some normal content"), 0640); err != nil {
		t.Fatal(err)
	}

	result := call(t, session, "search_within_files", map[string]any{
		"path":    sandbox,
		"pattern": "some",
	})
	assertAllowed(t, result)
	text := resultText(t, result)
	// Binary file must be skipped; real text file must match.
	if strings.Contains(text, "looks-like-text.txt") {
		t.Error("binary-content file should be skipped by isBinary check")
	}
	if !strings.Contains(text, "real.txt") {
		t.Errorf("real text file should match, got:\n%s", text)
	}
}
