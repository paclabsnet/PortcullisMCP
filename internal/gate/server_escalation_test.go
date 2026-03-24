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
	"strings"
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// newGateForEscalationTests returns a minimal Gate with the given Guard config.
func newGateForEscalationTests(guardCfg GuardConfig) *Gate {
	return &Gate{
		cfg: Config{Guard: guardCfg},
	}
}

// ---- isProactive ------------------------------------------------------------

func TestIsProactive_Default(t *testing.T) {
	g := newGateForEscalationTests(GuardConfig{})
	if g.isProactive() {
		t.Error("isProactive() = true for empty strategy, want false")
	}
}

func TestIsProactive_UserDriven(t *testing.T) {
	g := newGateForEscalationTests(GuardConfig{ApprovalManagementStrategy: "user-driven"})
	if g.isProactive() {
		t.Error("isProactive() = true for user-driven strategy, want false")
	}
}

func TestIsProactive_Proactive(t *testing.T) {
	g := newGateForEscalationTests(GuardConfig{ApprovalManagementStrategy: "proactive"})
	if !g.isProactive() {
		t.Error("isProactive() = false for proactive strategy, want true")
	}
}

// ---- buildEscalationMessage -------------------------------------------------

func TestBuildEscalationMessage_UserDrivenMode(t *testing.T) {
	g := newGateForEscalationTests(GuardConfig{
		Endpoint:                   "http://guard.example.com",
		ApprovalManagementStrategy: "user-driven",
	})
	e := &shared.EscalationPendingError{
		Reason:        "needs approval",
		EscalationJTI: "test-jti",
		EscalationJWT: "header.payload.sig",
	}
	msg := g.buildEscalationMessage(e)

	if !strings.Contains(msg, "needs approval") {
		t.Errorf("message should contain reason; got: %s", msg)
	}
	// User-driven: URL uses ?token= with the JWT
	if !strings.Contains(msg, "?token=") {
		t.Errorf("user-driven message should contain ?token=; got: %s", msg)
	}
	if strings.Contains(msg, "?jti=") {
		t.Errorf("user-driven message should not contain ?jti=; got: %s", msg)
	}
}

func TestBuildEscalationMessage_ProactiveMode(t *testing.T) {
	g := newGateForEscalationTests(GuardConfig{
		Endpoint:                   "http://guard.example.com",
		ApprovalManagementStrategy: "proactive",
	})
	e := &shared.EscalationPendingError{
		Reason:        "needs approval",
		EscalationJTI: "test-jti-xyz",
		EscalationJWT: "header.payload.sig",
	}
	msg := g.buildEscalationMessage(e)

	// Proactive: URL uses ?jti= with the JTI
	if !strings.Contains(msg, "?jti=test-jti-xyz") {
		t.Errorf("proactive message should contain ?jti=test-jti-xyz; got: %s", msg)
	}
	if strings.Contains(msg, "?token=") {
		t.Errorf("proactive message should not contain ?token=; got: %s", msg)
	}
	if !strings.Contains(msg, "guard.example.com/approve") {
		t.Errorf("proactive message should contain guard approve path; got: %s", msg)
	}
}

func TestBuildEscalationMessage_CustomInstructions(t *testing.T) {
	g := &Gate{
		cfg: Config{
			Guard: GuardConfig{
				Endpoint:                   "http://guard.example.com",
				ApprovalManagementStrategy: "proactive",
			},
			Agent: AgentConfig{
				Approval: AgentApprovalConfig{
					Instructions: "Please visit {url} for: {reason}",
				},
			},
		},
	}
	e := &shared.EscalationPendingError{
		Reason:        "manager sign-off",
		EscalationJTI: "jti-abc",
	}
	msg := g.buildEscalationMessage(e)

	if !strings.HasPrefix(msg, "Please visit") {
		t.Errorf("custom instructions not used; got: %s", msg)
	}
	if !strings.Contains(msg, "manager sign-off") {
		t.Errorf("reason not substituted; got: %s", msg)
	}
	if !strings.Contains(msg, "jti-abc") {
		t.Errorf("jti not in URL; got: %s", msg)
	}
}

func TestBuildEscalationMessage_FallbackToReference(t *testing.T) {
	// When no JWT and no JTI are available, fall back to the Reference field.
	g := newGateForEscalationTests(GuardConfig{Endpoint: "http://guard.example.com"})
	e := &shared.EscalationPendingError{
		Reason:    "needs approval",
		Reference: "https://servicenow.example.com/ticket/INC123",
	}
	msg := g.buildEscalationMessage(e)

	if !strings.Contains(msg, "servicenow.example.com") {
		t.Errorf("expected Reference URL as fallback; got: %s", msg)
	}
}

func TestBuildEscalationMessage_NoGuardEndpoint(t *testing.T) {
	// When Guard endpoint is not configured, message still includes the reason.
	g := newGateForEscalationTests(GuardConfig{}) // no endpoint
	e := &shared.EscalationPendingError{
		Reason:        "needs approval",
		EscalationJWT: "header.payload.sig",
	}
	msg := g.buildEscalationMessage(e)

	if !strings.Contains(msg, "needs approval") {
		t.Errorf("message should contain reason; got: %s", msg)
	}
}

func TestBuildEscalationMessage_NoURL_MisconfiguredMessage(t *testing.T) {
	// When no URL can be constructed from any source, the message should
	// indicate misconfiguration rather than presenting a broken empty URL.
	g := newGateForEscalationTests(GuardConfig{Endpoint: "http://guard.example.com"})
	e := &shared.EscalationPendingError{
		Reason: "needs approval",
		// EscalationJTI, EscalationJWT, and Reference all empty
	}
	msg := g.buildEscalationMessage(e)

	if strings.Contains(msg, "Do not truncate") {
		t.Errorf("should not show URL instructions when no URL available; got: %s", msg)
	}
	if !strings.Contains(msg, "needs approval") {
		t.Errorf("message should still contain reason; got: %s", msg)
	}
	if !strings.Contains(msg, "misconfigured") {
		t.Errorf("message should indicate misconfiguration; got: %s", msg)
	}
}

func TestBuildEscalationMessage_DefaultInstructions(t *testing.T) {
	// When no custom instructions are configured, the default template is used.
	g := newGateForEscalationTests(GuardConfig{Endpoint: "http://guard.example.com"})
	e := &shared.EscalationPendingError{
		Reason:        "needs approval",
		EscalationJWT: "h.p.s",
	}
	msg := g.buildEscalationMessage(e)

	if !strings.Contains(msg, "Escalation required") {
		t.Errorf("default instructions should start with 'Escalation required'; got: %s", msg)
	}
}
