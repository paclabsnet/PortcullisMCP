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
	"errors"
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// TestSingleTenantProvider_Capabilities verifies that SingleTenantProvider
// enables all Gate features.
func TestSingleTenantProvider_Capabilities(t *testing.T) {
	p := NewSingleTenantProvider(nil, "")
	caps := p.Capabilities()

	for name, got := range map[string]bool{
		"AllowLocalFS":      caps.AllowLocalFS,
		"AllowManagementUI": caps.AllowManagementUI,
		"AllowGuardPeer":    caps.AllowGuardPeer,
		"AllowHumanInLoop":  caps.AllowHumanInLoop,
		"AllowNativeTools":  caps.AllowNativeTools,
	} {
		if !got {
			t.Errorf("SingleTenantProvider.Capabilities().%s = false, want true", name)
		}
	}
}

// TestSingleTenantProvider_MapPolicyError_NeverHandles verifies that
// SingleTenantProvider never intercepts policy errors, letting server.go's
// existing single-tenant logic handle them.
func TestSingleTenantProvider_MapPolicyError_NeverHandles(t *testing.T) {
	p := NewSingleTenantProvider(nil, "")
	cfg := &Config{}
	errs := []error{
		shared.ErrDenied,
		&shared.DenyError{Reason: "nope"},
		&shared.EscalationPendingError{Reason: "needs approval"},
		errors.New("transport error"),
	}
	for _, err := range errs {
		result, handled := p.MapPolicyError(context.Background(), err, "tool", "trace", cfg)
		if handled {
			t.Errorf("SingleTenantProvider.MapPolicyError(%T): handled=true, want false", err)
		}
		if result != nil {
			t.Errorf("SingleTenantProvider.MapPolicyError(%T): result non-nil, want nil", err)
		}
	}
}

// TestMultiTenantProvider_Capabilities verifies that MultiTenantProvider
// disables all Gate features.
func TestMultiTenantProvider_Capabilities(t *testing.T) {
	p := NewMultiTenantProvider("", nil, nil)
	caps := p.Capabilities()

	for name, got := range map[string]bool{
		"AllowLocalFS":      caps.AllowLocalFS,
		"AllowManagementUI": caps.AllowManagementUI,
		"AllowGuardPeer":    caps.AllowGuardPeer,
		"AllowHumanInLoop":  caps.AllowHumanInLoop,
		"AllowNativeTools":  caps.AllowNativeTools,
	} {
		if got {
			t.Errorf("MultiTenantProvider.Capabilities().%s = true, want false", name)
		}
	}
}

// TestMultiTenantProvider_MapPolicyError_InterceptsPolicy verifies that
// escalation and deny errors are intercepted and converted to an opaque marker.
func TestMultiTenantProvider_MapPolicyError_InterceptsPolicy(t *testing.T) {
	logChan := make(chan DecisionLogEntry, 10)
	p := NewMultiTenantProvider("", nil, logChan)
	cfg := &Config{
		Responsibility: ResponsibilityConfig{
			Escalation: EscalationConfig{NoEscalationMarker: "BLOCKED"},
		},
	}

	policyErrors := []error{
		shared.ErrDenied,
		&shared.DenyError{Reason: "unauthorized"},
		&shared.EscalationPendingError{Reason: "needs approval"},
	}

	for _, err := range policyErrors {
		result, handled := p.MapPolicyError(context.Background(), err, "tool", "trace-1", cfg)
		if !handled {
			t.Errorf("MapPolicyError(%T): handled=false, want true", err)
		}
		if result == nil || !result.IsError {
			t.Errorf("MapPolicyError(%T): expected IsError result", err)
		}
		// Drain log entry.
		select {
		case <-logChan:
		default:
			t.Errorf("MapPolicyError(%T): no SIEM log entry emitted", err)
		}
	}
}

// TestMultiTenantProvider_MapPolicyError_PassesInfraErrors verifies that
// infrastructure errors (transport failures, identity errors) are not
// intercepted so callers can distinguish policy decisions from outages.
func TestMultiTenantProvider_MapPolicyError_PassesInfraErrors(t *testing.T) {
	logChan := make(chan DecisionLogEntry, 10)
	p := NewMultiTenantProvider("", nil, logChan)
	cfg := &Config{}

	infraErrors := []error{
		errors.New("connection refused"),
		&shared.IdentityVerificationError{Reason: "token expired"},
	}

	for _, err := range infraErrors {
		result, handled := p.MapPolicyError(context.Background(), err, "tool", "trace-2", cfg)
		if handled {
			t.Errorf("MapPolicyError(%T): handled=true for infra error, want false", err)
		}
		if result != nil {
			t.Errorf("MapPolicyError(%T): non-nil result for infra error", err)
		}
		select {
		case entry := <-logChan:
			t.Errorf("MapPolicyError(%T): unexpected SIEM log for infra error: %+v", err, entry)
		default:
		}
	}
}
