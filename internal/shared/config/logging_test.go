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

// Package config (internal tests) — uses package config (not config_test) so
// that unexported helpers resolveLogLevel, parseLevel, and setupLogging can be
// tested directly.
package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// mustSetup calls setupLogging with a buffer and returns the buffer. It fails
// the test immediately if setup returns an error.
func mustSetup(t *testing.T, cfg LoggingConfig, mode, levelOverride string) *bytes.Buffer {
	t.Helper()
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })
	var buf bytes.Buffer
	if err := setupLogging(cfg, mode, levelOverride, &buf); err != nil {
		t.Fatalf("setupLogging: %v", err)
	}
	return &buf
}

func TestResolveLogLevel(t *testing.T) {
	tests := []struct {
		name          string
		cfg           LoggingConfig
		mode          string
		levelOverride string
		wantLevel     string
		wantNotice    bool
	}{
		{
			name:      "no yaml no cli defaults to info",
			cfg:       LoggingConfig{},
			mode:      ModeDev,
			wantLevel: "info",
		},
		{
			name:      "yaml level only uses yaml",
			cfg:       LoggingConfig{Level: "debug"},
			mode:      ModeDev,
			wantLevel: "debug",
		},
		{
			name:          "cli overrides yaml in dev mode",
			cfg:           LoggingConfig{Level: "info"},
			mode:          ModeDev,
			levelOverride: "debug",
			wantLevel:     "debug",
		},
		{
			name:          "cli overrides empty yaml in dev mode",
			cfg:           LoggingConfig{},
			mode:          ModeDev,
			levelOverride: "warn",
			wantLevel:     "warn",
		},
		{
			name:          "production ignores cli override uses yaml",
			cfg:           LoggingConfig{Level: "info"},
			mode:          ModeProduction,
			levelOverride: "debug",
			wantLevel:     "info",
			wantNotice:    true,
		},
		{
			name:          "production ignores cli falls back to default",
			cfg:           LoggingConfig{},
			mode:          ModeProduction,
			levelOverride: "debug",
			wantLevel:     "info",
			wantNotice:    true,
		},
		{
			name:      "production with yaml no cli does not emit notice",
			cfg:       LoggingConfig{Level: "warn"},
			mode:      ModeProduction,
			wantLevel: "warn",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLevel, gotNotice := resolveLogLevel(tc.cfg, tc.mode, tc.levelOverride)
			if gotLevel != tc.wantLevel {
				t.Errorf("level = %q, want %q", gotLevel, tc.wantLevel)
			}
			if gotNotice != tc.wantNotice {
				t.Errorf("emitNotice = %v, want %v", gotNotice, tc.wantNotice)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input   string
		want    slog.Level
		wantErr bool
	}{
		{"debug", slog.LevelDebug, false},
		{"DEBUG", slog.LevelDebug, false},
		{"Debug", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"INFO", slog.LevelInfo, false},
		{"", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"WARN", slog.LevelWarn, false},
		{"warning", slog.LevelWarn, false},
		{"WARNING", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"ERROR", slog.LevelError, false},
		{"trace", slog.LevelInfo, true},
		{"verbose", slog.LevelInfo, true},
		{"invalid", slog.LevelInfo, true},
	}
	for _, tc := range tests {
		name := tc.input
		if name == "" {
			name = "(empty)"
		}
		t.Run(name, func(t *testing.T) {
			got, err := parseLevel(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("parseLevel(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
				return
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("parseLevel(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestSetupLoggingOutputFiltering verifies that only messages at or above the
// effective level appear in the actual log output.
func TestSetupLoggingOutputFiltering(t *testing.T) {
	tests := []struct {
		level        string
		wantDebug    bool
		wantInfo     bool
		wantWarn     bool
		wantError    bool
	}{
		{"debug", true, true, true, true},
		{"info", false, true, true, true},
		{"warn", false, false, true, true},
		{"error", false, false, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.level, func(t *testing.T) {
			buf := mustSetup(t, LoggingConfig{Level: tc.level}, ModeDev, "")

			slog.Debug("debug-sentinel")
			slog.Info("info-sentinel")
			slog.Warn("warn-sentinel")
			slog.Error("error-sentinel")

			out := buf.String()
			check := func(sentinel string, want bool) {
				t.Helper()
				got := strings.Contains(out, sentinel)
				if got != want {
					t.Errorf("output contains %q = %v, want %v\nfull output:\n%s", sentinel, got, want, out)
				}
			}
			check("debug-sentinel", tc.wantDebug)
			check("info-sentinel", tc.wantInfo)
			check("warn-sentinel", tc.wantWarn)
			check("error-sentinel", tc.wantError)
		})
	}
}

// TestSetupLoggingFormat verifies that the json format produces JSON output and
// the default (text) format does not.
func TestSetupLoggingFormat(t *testing.T) {
	t.Run("json format", func(t *testing.T) {
		buf := mustSetup(t, LoggingConfig{Level: "info", Format: "json"}, ModeDev, "")
		slog.Info("probe")
		if !strings.Contains(buf.String(), `"msg"`) {
			t.Errorf("expected JSON output, got: %s", buf.String())
		}
	})
	t.Run("text format", func(t *testing.T) {
		buf := mustSetup(t, LoggingConfig{Level: "info", Format: "text"}, ModeDev, "")
		slog.Info("probe")
		if strings.Contains(buf.String(), `"msg"`) {
			t.Errorf("expected text output, got JSON: %s", buf.String())
		}
	})
}

// TestSetupLoggingCLIOverridesYAML verifies that CLI level beats YAML level
// in non-production mode and that debug messages are actually emitted.
func TestSetupLoggingCLIOverridesYAML(t *testing.T) {
	buf := mustSetup(t, LoggingConfig{Level: "info"}, ModeDev, "debug")
	slog.Debug("should-appear")
	if !strings.Contains(buf.String(), "should-appear") {
		t.Errorf("expected debug output when CLI overrides YAML info with debug; got: %s", buf.String())
	}
}

func TestSetupLoggingInvalidLevel(t *testing.T) {
	tests := []struct {
		name          string
		cfg           LoggingConfig
		levelOverride string
	}{
		{"invalid yaml level", LoggingConfig{Level: "trace"}, ""},
		{"invalid cli level", LoggingConfig{}, "verbose"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orig := slog.Default()
			t.Cleanup(func() { slog.SetDefault(orig) })
			var buf bytes.Buffer
			err := setupLogging(tc.cfg, ModeDev, tc.levelOverride, &buf)
			if err == nil {
				t.Error("expected error for invalid log level, got nil")
			}
		})
	}
}

// TestSetupLoggingProductionNotice verifies that the production-mode override
// notice is actually written to the log output.
func TestSetupLoggingProductionNotice(t *testing.T) {
	t.Run("notice emitted in production with cli override", func(t *testing.T) {
		buf := mustSetup(t, LoggingConfig{Level: "info"}, ModeProduction, "debug")
		if !strings.Contains(buf.String(), "NOTICE") {
			t.Errorf("expected NOTICE in output; got: %s", buf.String())
		}
		if !strings.Contains(buf.String(), "log-level") {
			t.Errorf("expected 'log-level' mention in output; got: %s", buf.String())
		}
	})
	t.Run("no notice in dev mode with cli override", func(t *testing.T) {
		buf := mustSetup(t, LoggingConfig{Level: "info"}, ModeDev, "debug")
		slog.Info("baseline") // ensure the logger is working
		if strings.Contains(buf.String(), "NOTICE") {
			t.Errorf("unexpected NOTICE in dev mode output; got: %s", buf.String())
		}
	})
	t.Run("no notice in production without cli override", func(t *testing.T) {
		buf := mustSetup(t, LoggingConfig{Level: "warn"}, ModeProduction, "")
		slog.Warn("baseline")
		if strings.Contains(buf.String(), "NOTICE") {
			t.Errorf("unexpected NOTICE when no cli override; got: %s", buf.String())
		}
	})
}
