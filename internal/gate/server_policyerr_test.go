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
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

func newGateForPolicyErrTests(guardEndpoint string) *Gate {
	return &Gate{
		cfg: Config{
			Keep:  KeepConfig{Endpoint: "http://keep.example.com"},
			Guard: GuardConfig{Endpoint: guardEndpoint},
		},
	}
}

// policyErrText extracts the text from the first TextContent in the result.
func policyErrText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("result has no content")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected *mcp.TextContent, got %T", result.Content[0])
	}
	return tc.Text
}

func TestPolicyErrToResult_Deny(t *testing.T) {
	g := newGateForPolicyErrTests("http://guard.example.com")
	result, retErr := g.policyErrToResult(shared.ErrDenied, "test-tool", "req-1")
	if retErr != nil {
		t.Fatalf("expected nil error, got: %v", retErr)
	}
	if !result.IsError {
		t.Error("result.IsError should be true for deny")
	}
	text := policyErrText(t, result)
	if !strings.HasPrefix(text, "Access denied:") {
		t.Errorf("deny message should start with 'Access denied:'; got: %s", text)
	}
}

func TestPolicyErrToResult_Escalation_WithGuard(t *testing.T) {
	g := newGateForPolicyErrTests("http://guard.example.com")
	e := &shared.EscalationPendingError{
		Reason:        "needs approval",
		EscalationJTI: "test-jti",
		PendingJWT: "header.payload.sig",
	}
	result, retErr := g.policyErrToResult(e, "test-tool", "req-2")
	if retErr != nil {
		t.Fatalf("expected nil error, got: %v", retErr)
	}
	if !result.IsError {
		t.Error("result.IsError should be true for escalation")
	}
	text := policyErrText(t, result)
	if strings.HasPrefix(text, "Access denied:") {
		t.Errorf("escalation with Guard configured should not be formatted as deny; got: %s", text)
	}
	if !strings.Contains(text, "needs approval") {
		t.Errorf("escalation message should contain the reason; got: %s", text)
	}
}

func TestPolicyErrToResult_Escalation_NoGuard_TreatedAsDeny(t *testing.T) {
	// Without a Guard endpoint, escalation can never complete — must be treated as deny.
	g := newGateForPolicyErrTests("") // no Guard endpoint
	e := &shared.EscalationPendingError{
		Reason:        "needs manager approval",
		EscalationJTI: "test-jti",
		PendingJWT: "header.payload.sig",
	}
	result, retErr := g.policyErrToResult(e, "test-tool", "req-3")
	if retErr != nil {
		t.Fatalf("expected nil error, got: %v", retErr)
	}
	if !result.IsError {
		t.Error("result.IsError should be true")
	}
	text := policyErrText(t, result)
	if !strings.HasPrefix(text, "Access denied:") {
		t.Errorf("escalation without Guard should be formatted as deny; got: %s", text)
	}
	if !strings.Contains(text, "needs manager approval") {
		t.Errorf("deny message should contain the reason; got: %s", text)
	}
}

func TestPolicyErrToResult_UnknownError_ReturnedAsIs(t *testing.T) {
	g := newGateForPolicyErrTests("http://guard.example.com")
	unexpectedErr := errors.New("connection refused")
	result, retErr := g.policyErrToResult(unexpectedErr, "test-tool", "req-4")
	if result != nil {
		t.Error("expected nil result for unknown error")
	}
	if retErr == nil {
		t.Fatal("expected error to be returned for unknown error type")
	}
	if retErr != unexpectedErr {
		t.Errorf("returned error = %v, want %v", retErr, unexpectedErr)
	}
}
