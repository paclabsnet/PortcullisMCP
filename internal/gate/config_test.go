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

import "testing"

func TestConfig_Validate_ApprovalManagementStrategy(t *testing.T) {
	tests := []struct {
		strategy string
		wantErr  bool
	}{
		{"", false},
		{"user-driven", false},
		{"proactive", false},
		{"Proactive", true},
		{"USER-DRIVEN", true},
		{"proactve", true}, // typo
		{"unknown", true},
	}
	for _, tc := range tests {
		t.Run(tc.strategy, func(t *testing.T) {
			cfg := Config{Guard: GuardConfig{ApprovalManagementStrategy: tc.strategy}}
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
