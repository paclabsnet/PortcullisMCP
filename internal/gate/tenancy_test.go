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
	"testing"
)

// TestSingleTenantProvider_Capabilities verifies that SingleTenantProvider
// enables all Gate features.
func TestSingleTenantProvider_Capabilities(t *testing.T) {
	p := NewSingleTenantProvider(nil, "")
	caps := p.Capabilities()

	for name, got := range map[string]bool{
		"AllowLocalFS":      caps.AllowLocalFS,
		"AllowManagementUI": caps.AllowManagementUI,
		"AllowNativeTools":  caps.AllowNativeTools,
	} {
		if !got {
			t.Errorf("SingleTenantProvider.Capabilities().%s = false, want true", name)
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
		"AllowNativeTools":  caps.AllowNativeTools,
	} {
		if got {
			t.Errorf("MultiTenantProvider.Capabilities().%s = true, want false", name)
		}
	}
}
