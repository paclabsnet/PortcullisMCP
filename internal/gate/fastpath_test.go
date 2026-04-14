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
			Responsibility: ResponsibilityConfig{
				Tools: ToolsConfig{
					LocalFS: LocalFSConfig{
						Workspace: SandboxConfig{Directory: sandbox},
						Forbidden: ForbiddenConfig{Directories: protected},
					},
				},
			},
		},
	}
}

func TestFastPath(t *testing.T) {
	// "read_file" is intentionally used as the tool name throughout this test.
	// It is not present in toolCategory, so effectiveStrategy always returns the
	// default "allow". This isolates the sandbox/forbidden path logic from
	// strategy behaviour; strategy is covered separately in TestStrategyPrecedence
	// and related tests.
	//
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
		{
			name:     "deeply nested non-existent path inside sandbox",
			toolName: "write_file",
			args:     map[string]any{"path": filepath.Join(sandbox, "a", "b", "c", "new.txt")},
			want:     FastPathAllow,
		},
		{
			name:     "deeply nested non-existent path outside sandbox",
			toolName: "write_file",
			args:     map[string]any{"path": filepath.Join(outside, "a", "b", "c", "new.txt")},
			want:     FastPathForward,
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
	_ = os.WriteFile(protectedFile, []byte("secret"), 0640)

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
	_ = os.WriteFile(protectedFile, []byte("x"), 0640)

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

func TestFastPath_MultiSandbox(t *testing.T) {
	parent := t.TempDir()
	sandboxA := filepath.Join(parent, "sandbox-a")
	sandboxB := filepath.Join(parent, "sandbox-b")
	protected := filepath.Join(parent, "protected")
	outside := filepath.Join(parent, "outside")
	for _, d := range []string{sandboxA, sandboxB, protected, outside} {
		_ = os.MkdirAll(d, 0750)
	}

	fileA := filepath.Join(sandboxA, "a.txt")
	fileB := filepath.Join(sandboxB, "b.txt")
	fileProtected := filepath.Join(protected, "secret.txt")
	fileOutside := filepath.Join(outside, "other.txt")
	for _, f := range []string{fileA, fileB, fileProtected, fileOutside} {
		_ = os.WriteFile(f, []byte("x"), 0640)
	}

	g := &Gate{
		cfg: Config{
			Responsibility: ResponsibilityConfig{
				Tools: ToolsConfig{
					LocalFS: LocalFSConfig{
						Workspace: SandboxConfig{Directories: []string{sandboxA, sandboxB}},
						Forbidden: ForbiddenConfig{Directories: []string{protected}},
					},
				},
			},
		},
	}
	ctx := context.Background()

	tests := []struct {
		name string
		args map[string]any
		want FastPathResult
	}{
		{
			name: "file in sandbox A is allowed",
			args: map[string]any{"path": fileA},
			want: FastPathAllow,
		},
		{
			name: "file in sandbox B is allowed",
			args: map[string]any{"path": fileB},
			want: FastPathAllow,
		},
		{
			name: "file outside all sandboxes forwards to Keep",
			args: map[string]any{"path": fileOutside},
			want: FastPathForward,
		},
		{
			name: "protected path is denied even when not in any sandbox",
			args: map[string]any{"path": fileProtected},
			want: FastPathDeny,
		},
		{
			name: "copy spanning both sandboxes forwards to Keep (not all in one sandbox)",
			args: map[string]any{"source": fileA, "destination": fileB},
			want: FastPathForward,
		},
		{
			name: "copy within sandbox A is allowed",
			args: map[string]any{"source": fileA, "destination": filepath.Join(sandboxA, "copy.txt")},
			want: FastPathAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := g.FastPath(ctx, "read_file", tt.args)
			if got != tt.want {
				t.Errorf("FastPath() = %s, want %s", got, tt.want)
			}
		})
	}
}

// newTestGateWithStrategy builds a minimal Gate with a workspace, forbidden
// directories, and a strategy config for strategy-related FastPath tests.
func newTestGateWithStrategy(dirs []string, protected []string, strategy LocalFSStrategyConfig) *Gate {
	return &Gate{
		cfg: Config{
			Responsibility: ResponsibilityConfig{
				Tools: ToolsConfig{
					LocalFS: LocalFSConfig{
						Workspace: SandboxConfig{Directories: dirs},
						Forbidden: ForbiddenConfig{Directories: protected},
						Strategy:  strategy,
					},
				},
			},
		},
	}
}

func TestWildcardWorkspace(t *testing.T) {
	outside := t.TempDir()
	protected := t.TempDir()
	protectedFile := filepath.Join(protected, "secret.txt")
	_ = os.WriteFile(protectedFile, []byte("x"), 0640)

	g := newTestGateWithStrategy([]string{"*"}, []string{protected}, LocalFSStrategyConfig{})
	ctx := context.Background()

	t.Run("any path is allowed with wildcard workspace", func(t *testing.T) {
		got, _ := g.FastPath(ctx, "read_text_file", map[string]any{"path": filepath.Join(outside, "file.txt")})
		if got != FastPathAllow {
			t.Errorf("FastPath() = %s, want allow", got)
		}
	})

	t.Run("forbidden path is denied even with wildcard workspace", func(t *testing.T) {
		got, _ := g.FastPath(ctx, "read_text_file", map[string]any{"path": protectedFile})
		if got != FastPathDeny {
			t.Errorf("FastPath() = %s, want deny", got)
		}
	})
}

func TestStrategyPrecedence(t *testing.T) {
	sandbox := t.TempDir()
	sandboxFile := filepath.Join(sandbox, "file.txt")
	_ = os.WriteFile(sandboxFile, []byte("x"), 0640)
	ctx := context.Background()

	t.Run("tool override takes precedence over category", func(t *testing.T) {
		// Category says "allow" but tool-specific says "deny".
		g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{
			Read:         "allow",
			ReadTextFile: "deny",
		})
		got, _ := g.FastPath(ctx, "read_text_file", map[string]any{"path": sandboxFile})
		if got != FastPathDeny {
			t.Errorf("FastPath() = %s, want deny", got)
		}
	})

	t.Run("category applies when no tool override is set", func(t *testing.T) {
		// Category says "verify"; no tool override.
		g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{
			Read: "verify",
		})
		got, _ := g.FastPath(ctx, "read_text_file", map[string]any{"path": sandboxFile})
		if got != FastPathForward {
			t.Errorf("FastPath() = %s, want forward", got)
		}
	})

	t.Run("tool override verify beats category allow", func(t *testing.T) {
		g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{
			Delete:     "allow",
			DeleteFile: "verify",
		})
		got, _ := g.FastPath(ctx, "delete_file", map[string]any{"path": sandboxFile})
		if got != FastPathForward {
			t.Errorf("FastPath() = %s, want forward", got)
		}
	})
}

func TestGlobalDenyVerify(t *testing.T) {
	sandbox := t.TempDir()
	outside := t.TempDir()
	sandboxFile := filepath.Join(sandbox, "file.txt")
	_ = os.WriteFile(sandboxFile, []byte("x"), 0640)
	outsideFile := filepath.Join(outside, "file.txt")
	_ = os.WriteFile(outsideFile, []byte("x"), 0640)
	ctx := context.Background()

	t.Run("deny is global — applies inside workspace", func(t *testing.T) {
		g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{Delete: "deny"})
		got, _ := g.FastPath(ctx, "delete_file", map[string]any{"path": sandboxFile})
		if got != FastPathDeny {
			t.Errorf("FastPath() = %s, want deny", got)
		}
	})

	t.Run("deny is global — applies outside workspace", func(t *testing.T) {
		g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{Delete: "deny"})
		got, _ := g.FastPath(ctx, "delete_file", map[string]any{"path": outsideFile})
		if got != FastPathDeny {
			t.Errorf("FastPath() = %s, want deny", got)
		}
	})

	t.Run("verify is global — applies inside workspace", func(t *testing.T) {
		g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{Write: "verify"})
		got, _ := g.FastPath(ctx, "write_file", map[string]any{"path": sandboxFile})
		if got != FastPathForward {
			t.Errorf("FastPath() = %s, want forward", got)
		}
	})

	t.Run("verify is global — applies outside workspace", func(t *testing.T) {
		g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{Write: "verify"})
		got, _ := g.FastPath(ctx, "write_file", map[string]any{"path": outsideFile})
		if got != FastPathForward {
			t.Errorf("FastPath() = %s, want forward", got)
		}
	})

	t.Run("allow outside workspace downgrades to forward", func(t *testing.T) {
		g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{Read: "allow"})
		got, _ := g.FastPath(ctx, "read_text_file", map[string]any{"path": outsideFile})
		if got != FastPathForward {
			t.Errorf("FastPath() = %s, want forward", got)
		}
	})
}

func TestForbiddenOverride(t *testing.T) {
	// Even with wildcard workspace and allow strategy, forbidden wins.
	forbidden := t.TempDir()
	forbiddenFile := filepath.Join(forbidden, "secret.txt")
	_ = os.WriteFile(forbiddenFile, []byte("x"), 0640)

	g := newTestGateWithStrategy([]string{"*"}, []string{forbidden}, LocalFSStrategyConfig{
		Read: "allow",
	})
	ctx := context.Background()

	got, _ := g.FastPath(ctx, "read_text_file", map[string]any{"path": forbiddenFile})
	if got != FastPathDeny {
		t.Errorf("FastPath() = %s, want deny (forbidden overrides wildcard+allow)", got)
	}
}

func TestImplicitVerify(t *testing.T) {
	// Paths outside the workspace with strategy "allow" (default) must forward.
	sandbox := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "file.txt")
	_ = os.WriteFile(outsideFile, []byte("x"), 0640)

	g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{})
	ctx := context.Background()

	got, _ := g.FastPath(ctx, "read_text_file", map[string]any{"path": outsideFile})
	if got != FastPathForward {
		t.Errorf("FastPath() = %s, want forward (implicit verify outside workspace)", got)
	}
}

func TestOperationMapping(t *testing.T) {
	// copy_file and move_file must be governed by the "write" strategy.
	sandbox := t.TempDir()
	fileA := filepath.Join(sandbox, "a.txt")
	fileB := filepath.Join(sandbox, "b.txt")
	_ = os.WriteFile(fileA, []byte("x"), 0640)
	_ = os.WriteFile(fileB, []byte("x"), 0640)

	ctx := context.Background()

	for _, toolName := range []string{"copy_file", "move_file"} {
		t.Run(toolName+" governed by write strategy deny", func(t *testing.T) {
			g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{Write: "deny"})
			got, _ := g.FastPath(ctx, toolName, map[string]any{
				"source":      fileA,
				"destination": fileB,
			})
			if got != FastPathDeny {
				t.Errorf("FastPath(%s) = %s, want deny", toolName, got)
			}
		})

		t.Run(toolName+" governed by write strategy verify", func(t *testing.T) {
			g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{Write: "verify"})
			got, _ := g.FastPath(ctx, toolName, map[string]any{
				"source":      fileA,
				"destination": fileB,
			})
			if got != FastPathForward {
				t.Errorf("FastPath(%s) = %s, want forward", toolName, got)
			}
		})
	}
}

func TestDirectoryArgExtraction(t *testing.T) {
	// The "directory" argument key must be treated as a path.
	sandbox := t.TempDir()
	outside := t.TempDir()
	ctx := context.Background()
	g := newTestGateWithStrategy([]string{sandbox}, nil, LocalFSStrategyConfig{})

	t.Run("directory arg inside sandbox is allowed", func(t *testing.T) {
		got, _ := g.FastPath(ctx, "list_directory", map[string]any{"directory": sandbox})
		if got != FastPathAllow {
			t.Errorf("FastPath() = %s, want allow", got)
		}
	})

	t.Run("directory arg outside sandbox is forwarded", func(t *testing.T) {
		got, _ := g.FastPath(ctx, "list_directory", map[string]any{"directory": outside})
		if got != FastPathForward {
			t.Errorf("FastPath() = %s, want forward", got)
		}
	})
}

func TestSandboxConfig_EffectiveDirs(t *testing.T) {
	tests := []struct {
		name string
		cfg  SandboxConfig
		want []string
	}{
		{
			name: "empty config returns empty slice",
			cfg:  SandboxConfig{},
			want: nil,
		},
		{
			name: "only Directory set",
			cfg:  SandboxConfig{Directory: "/a"},
			want: []string{"/a"},
		},
		{
			name: "only Directories set",
			cfg:  SandboxConfig{Directories: []string{"/b", "/c"}},
			want: []string{"/b", "/c"},
		},
		{
			name: "both set, no overlap",
			cfg:  SandboxConfig{Directory: "/a", Directories: []string{"/b", "/c"}},
			want: []string{"/a", "/b", "/c"},
		},
		{
			name: "Directory duplicated in Directories is deduplicated",
			cfg:  SandboxConfig{Directory: "/a", Directories: []string{"/a", "/b"}},
			want: []string{"/a", "/b"},
		},
		{
			name: "duplicates within Directories are deduplicated",
			cfg:  SandboxConfig{Directories: []string{"/a", "/b", "/a"}},
			want: []string{"/a", "/b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.EffectiveDirs()
			if len(got) != len(tt.want) {
				t.Fatalf("EffectiveDirs() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("EffectiveDirs()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
