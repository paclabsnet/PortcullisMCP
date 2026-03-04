package keep

import (
	"context"
	"testing"
)

func TestRouter_CallTool_UnknownBackend(t *testing.T) {
	cfg := map[string]BackendConfig{}
	router := NewRouter(cfg)

	_, err := router.CallTool(context.Background(), "nonexistent", "tool", nil)
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}

	expectedMsg := "unknown backend"
	if err.Error()[:len(expectedMsg)] != expectedMsg {
		t.Errorf("error message = %q, want prefix %q", err.Error(), expectedMsg)
	}
}

func TestRouter_BuildBackendTransport_Stdio(t *testing.T) {
	cfg := BackendConfig{
		Type:    "stdio",
		Command: "echo",
		Args:    []string{"hello"},
		Env: map[string]string{
			"TEST_VAR": "test-value",
		},
	}

	transport, err := buildBackendTransport(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestRouter_BuildBackendTransport_StdioMissingCommand(t *testing.T) {
	cfg := BackendConfig{
		Type: "stdio",
		// Command is missing
	}

	_, err := buildBackendTransport(cfg)
	if err == nil {
		t.Fatal("expected error for stdio backend without command, got nil")
	}

	expectedMsg := "requires a command"
	if err.Error()[len(err.Error())-len(expectedMsg):] != expectedMsg {
		t.Errorf("error message = %q, want suffix %q", err.Error(), expectedMsg)
	}
}

func TestRouter_BuildBackendTransport_UnsupportedType(t *testing.T) {
	cfg := BackendConfig{
		Type: "unsupported",
	}

	_, err := buildBackendTransport(cfg)
	if err == nil {
		t.Fatal("expected error for unsupported backend type, got nil")
	}

	expectedMsg := "unsupported backend type"
	if err.Error()[:len(expectedMsg)] != expectedMsg {
		t.Errorf("error message = %q, want prefix %q", err.Error(), expectedMsg)
	}
}

func TestRouter_ListAllTools_EmptyBackends(t *testing.T) {
	cfg := map[string]BackendConfig{}
	router := NewRouter(cfg)

	tools, err := router.ListAllTools(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Empty backends returns nil or empty slice
	if len(tools) != 0 {
		t.Errorf("expected empty tools list, got %d tools", len(tools))
	}
}
