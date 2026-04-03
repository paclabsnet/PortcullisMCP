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

package main

import (
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/keep"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name         string
		argv         []string
		wantLogLevel string
		wantConfig   string
		wantErr      bool
	}{
		{
			name:         "defaults when no flags given",
			argv:         []string{},
			wantLogLevel: "",
			wantConfig:   "/etc/portcullis/keep.yaml",
		},
		{
			name:         "log-level flag is parsed",
			argv:         []string{"--log-level", "info"},
			wantLogLevel: "info",
			wantConfig:   "/etc/portcullis/keep.yaml",
		},
		{
			name:         "config flag is parsed",
			argv:         []string{"--config", "/run/keep.yaml"},
			wantLogLevel: "",
			wantConfig:   "/run/keep.yaml",
		},
		{
			name:         "both flags parsed together",
			argv:         []string{"--log-level", "error", "--config", "/run/keep.yaml"},
			wantLogLevel: "error",
			wantConfig:   "/run/keep.yaml",
		},
		{
			name:    "unknown flag returns error",
			argv:    []string{"--unknown-flag"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := parseFlags(tc.argv)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseFlags error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if a.logLevel != tc.wantLogLevel {
				t.Errorf("logLevel = %q, want %q", a.logLevel, tc.wantLogLevel)
			}
			if a.config != tc.wantConfig {
				t.Errorf("config = %q, want %q", a.config, tc.wantConfig)
			}
		})
	}
}

func TestApplyLoggingForwardsArgs(t *testing.T) {
	orig := logSetupFn
	defer func() { logSetupFn = orig }()

	var capturedLevel, capturedMode string
	logSetupFn = func(_ cfgloader.LoggingConfig, mode, level string) error {
		capturedMode = mode
		capturedLevel = level
		return nil
	}

	if err := applyLogging(keep.Config{Mode: "dev"}, cliArgs{logLevel: "warn"}); err != nil {
		t.Fatalf("applyLogging: %v", err)
	}
	if capturedLevel != "warn" {
		t.Errorf("capturedLevel = %q, want %q", capturedLevel, "warn")
	}
	if capturedMode != "dev" {
		t.Errorf("capturedMode = %q, want %q", capturedMode, "dev")
	}
}
