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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestForbiddenSubtreesAreSkipped(t *testing.T) {
	sandbox := t.TempDir()
	mustWrite := func(rel, content string) {
		p := filepath.Join(sandbox, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("public/note.txt", "hello public\n")
	mustWrite("top.txt", "hello top\n")
	mustWrite(".secrets/key", "TOPSECRET-KEY hello\n")
	mustWrite(".secrets/deep/more.txt", "TOPSECRET-DEEP hello\n")

	srv, session, err := Connect(context.Background(), []string{sandbox})
	if err != nil {
		t.Fatal(err)
	}
	// "missing/later" does not exist on disk; it must be tolerated.
	srv.SetForbiddenDirs([]string{filepath.Join(sandbox, ".secrets"), filepath.Join(sandbox, "missing", "later")})

	symlinks := runtime.GOOS != "windows"
	if symlinks {
		if err := os.Symlink(filepath.Join(sandbox, ".secrets", "key"), filepath.Join(sandbox, "public", "keylink.txt")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(sandbox, ".secrets"), filepath.Join(sandbox, "dirlink")); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name       string
		tool       string
		args       map[string]any
		wantErr    bool
		mustHave   []string
		mustNotHas []string
	}{
		{
			name:       "search_within_files at root skips forbidden",
			tool:       "search_within_files",
			args:       map[string]any{"path": ".", "pattern": "hello"},
			mustHave:   []string{"top.txt:1: hello top", "note.txt:1: hello public"},
			mustNotHas: []string{"TOPSECRET", ".secrets"},
		},
		{
			name:       "search_files skips forbidden",
			tool:       "search_files",
			args:       map[string]any{"path": ".", "pattern": "**/*"},
			mustHave:   []string{"top.txt", "note.txt"},
			mustNotHas: []string{"key", "more.txt", ".secrets", "deep"},
		},
		{
			name:       "directory_tree omits forbidden",
			tool:       "directory_tree",
			args:       map[string]any{"path": "."},
			mustHave:   []string{"top.txt", "note.txt"},
			mustNotHas: []string{".secrets", "key", "more.txt", "deep"},
		},
		{
			name:       "list_directory omits forbidden",
			tool:       "list_directory",
			args:       map[string]any{"path": "."},
			mustHave:   []string{"top.txt", "public/"},
			mustNotHas: []string{".secrets"},
		},
		{
			name:       "list_directory_with_sizes omits forbidden",
			tool:       "list_directory_with_sizes",
			args:       map[string]any{"path": "."},
			mustHave:   []string{"top.txt", "public/"},
			mustNotHas: []string{".secrets"},
		},
		{
			name:    "list_directory on forbidden dir is denied",
			tool:    "list_directory",
			args:    map[string]any{"path": ".secrets"},
			wantErr: true,
		},
		{
			name:    "read_text_file on forbidden file is denied",
			tool:    "read_text_file",
			args:    map[string]any{"path": ".secrets/key"},
			wantErr: true,
		},
		{
			name:    "search_within_files rooted in forbidden dir is denied",
			tool:    "search_within_files",
			args:    map[string]any{"path": ".secrets", "pattern": "hello"},
			wantErr: true,
		},
		{
			name:     "non-forbidden file is still readable",
			tool:     "read_text_file",
			args:     map[string]any{"path": "top.txt"},
			mustHave: []string{"hello top"},
		},
	}
	if symlinks {
		tests = append(tests,
			struct {
				name       string
				tool       string
				args       map[string]any
				wantErr    bool
				mustHave   []string
				mustNotHas []string
			}{
				name:       "symlinks into forbidden are not followed by search",
				tool:       "search_within_files",
				args:       map[string]any{"path": "public", "pattern": "TOPSECRET"},
				mustHave:   []string{"No matches found"},
				mustNotHas: []string{"keylink"},
			},
			struct {
				name       string
				tool       string
				args       map[string]any
				wantErr    bool
				mustHave   []string
				mustNotHas []string
			}{
				name:       "symlink to forbidden dir is not listed",
				tool:       "list_directory",
				args:       map[string]any{"path": "."},
				mustHave:   []string{"top.txt"},
				mustNotHas: []string{"dirlink"},
			},
			struct {
				name       string
				tool       string
				args       map[string]any
				wantErr    bool
				mustHave   []string
				mustNotHas []string
			}{
				name:    "reading through symlink into forbidden is denied",
				tool:    "read_text_file",
				args:    map[string]any{"path": "dirlink/key"},
				wantErr: true,
			},
		)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := call(t, session, tc.tool, tc.args)
			if tc.wantErr {
				assertDenied(t, res)
				return
			}
			assertAllowed(t, res)
			text := resultText(t, res)
			for _, s := range tc.mustHave {
				if !strings.Contains(text, s) {
					t.Errorf("output missing %q:\n%s", s, text)
				}
			}
			for _, s := range tc.mustNotHas {
				if strings.Contains(text, s) {
					t.Errorf("output leaks %q:\n%s", s, text)
				}
			}
		})
	}
}
