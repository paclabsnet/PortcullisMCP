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
	"runtime"
	"testing"
)

// newTestGate builds a minimal Gate with only the config fields that FastPath
// needs. No network connections or token stores are initialised.
func newTestGate(sandbox string, protected []string) *Gate {
	return &Gate{
		cfg: Config{
			Sandbox:        SandboxConfig{Directory: sandbox},
			ProtectedPaths: protected,
		},
	}
}

func TestFastPath(t *testing.T) {
	// Create a parent dir so sandbox and protected are siblings, enabling
	// reliable path-traversal test cases.
	parent := t.TempDir()
	sandbox := filepath.Join(parent, "sandbox")
	protected := filepath.Join(parent, "protected")
	if err := os.MkdirAll(sandbox, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(protected, 0750); err != nil {
		t.Fatal(err)
	}

	// Seed files used in tests.
	sandboxFile := filepath.Join(sandbox, "hello.txt")
	if err := os.WriteFile(sandboxFile, []byte("hello"), 0640); err != nil {
		t.Fatal(err)
	}
	protectedFile := filepath.Join(protected, "secret.txt")
	if err := os.WriteFile(protectedFile, []byte("secret"), 0640); err != nil {
		t.Fatal(err)
	}

	outside := t.TempDir() // entirely separate tree

	g := newTestGate(sandbox, []string{protected})
	ctx := context.Background()

	tests := []struct {
		name     string
		toolName string
		args     map[string]any
		want     FastPathResult
	}{
		// --- Allow ---
		{
			name:     "existing file in sandbox",
			toolName: "read_file",
			args:     map[string]any{"path": sandboxFile},
			want:     FastPathAllow,
		},
		{
			name:     "sandbox root directory",
			toolName: "list_directory",
			args:     map[string]any{"path": sandbox},
			want:     FastPathAllow,
		},
		{
			name:     "non-existent file inside sandbox (write target)",
			toolName: "write_file",
			args:     map[string]any{"path": filepath.Join(sandbox, "new.txt")},
			want:     FastPathAllow,
		},
		{
			name:     "nested subdirectory inside sandbox",
			toolName: "list_directory",
			args:     map[string]any{"path": filepath.Join(sandbox, "subdir")},
			want:     FastPathAllow,
		},

		// --- Deny ---
		{
			name:     "file inside protected directory",
			toolName: "read_file",
			args:     map[string]any{"path": protectedFile},
			want:     FastPathDeny,
		},
		{
			name:     "protected directory root",
			toolName: "list_directory",
			args:     map[string]any{"path": protected},
			want:     FastPathDeny,
		},
		{
			name:     "path traversal from sandbox into protected",
			toolName: "read_file",
			args: map[string]any{
				"path": filepath.Join(sandbox, "..", filepath.Base(protected), "secret.txt"),
			},
			want: FastPathDeny,
		},
		{
			name:     "path traversal to protected root",
			toolName: "list_directory",
			args: map[string]any{
				"path": filepath.Join(sandbox, "..", filepath.Base(protected)),
			},
			want: FastPathDeny,
		},

		// --- Forward ---
		{
			name:     "path outside sandbox and protected",
			toolName: "read_file",
			args:     map[string]any{"path": filepath.Join(outside, "file.txt")},
			want:     FastPathForward,
		},
		{
			name:     "parent of sandbox (outside)",
			toolName: "list_directory",
			args:     map[string]any{"path": parent},
			want:     FastPathForward,
		},
		{
			name:     "no path argument",
			toolName: "some_api_tool",
			args:     map[string]any{"query": "hello"},
			want:     FastPathForward,
		},
		{
			name:     "path argument is not a string",
			toolName: "read_file",
			args:     map[string]any{"path": 42},
			want:     FastPathForward,
		},
		{
			name:     "empty path string",
			toolName: "read_file",
			args:     map[string]any{"path": ""},
			want:     FastPathForward,
		},
		{
			name:     "empty args map",
			toolName: "read_file",
			args:     map[string]any{},
			want:     FastPathForward,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := g.FastPath(ctx, tt.toolName, tt.args)
			if err != nil {
				t.Fatalf("FastPath returned unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("FastPath() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestFastPath_Symlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}

	parent := t.TempDir()
	sandbox := filepath.Join(parent, "sandbox")
	protected := filepath.Join(parent, "protected")
	if err := os.MkdirAll(sandbox, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(protected, 0750); err != nil {
		t.Fatal(err)
	}
	protectedFile := filepath.Join(protected, "secret.txt")
	if err := os.WriteFile(protectedFile, []byte("secret"), 0640); err != nil {
		t.Fatal(err)
	}

	g := newTestGate(sandbox, []string{protected})
	ctx := context.Background()

	t.Run("symlink inside sandbox pointing to protected file", func(t *testing.T) {
		link := filepath.Join(sandbox, "escape.txt")
		if err := os.Symlink(protectedFile, link); err != nil {
			t.Skipf("could not create symlink: %v", err)
		}
		got, err := g.FastPath(ctx, "read_file", map[string]any{"path": link})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// After symlink resolution the path lands in protected → deny.
		if got != FastPathDeny {
			t.Errorf("FastPath() = %s, want deny", got)
		}
	})

	t.Run("symlink inside sandbox pointing outside (not protected)", func(t *testing.T) {
		outside := t.TempDir()
		link := filepath.Join(sandbox, "outside.txt")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("could not create symlink: %v", err)
		}
		got, err := g.FastPath(ctx, "read_file", map[string]any{"path": link})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Resolves outside both sandbox and protected → forward.
		if got != FastPathForward {
			t.Errorf("FastPath() = %s, want forward", got)
		}
	})
}

func TestFastPath_NoSandbox(t *testing.T) {
	// When no sandbox is configured, no request is fast-path allowed;
	// filesystem ops must go to Keep.
	protected := t.TempDir()
	protectedFile := filepath.Join(protected, "secret.txt")
	if err := os.WriteFile(protectedFile, []byte("x"), 0640); err != nil {
		t.Fatal(err)
	}

	g := newTestGate("", []string{protected})
	ctx := context.Background()

	t.Run("file in protected still denied without sandbox", func(t *testing.T) {
		got, _ := g.FastPath(ctx, "read_file", map[string]any{"path": protectedFile})
		if got != FastPathDeny {
			t.Errorf("FastPath() = %s, want deny", got)
		}
	})

	t.Run("arbitrary path forwards when no sandbox configured", func(t *testing.T) {
		got, _ := g.FastPath(ctx, "read_file", map[string]any{"path": t.TempDir()})
		if got != FastPathForward {
			t.Errorf("FastPath() = %s, want forward", got)
		}
	})
}
