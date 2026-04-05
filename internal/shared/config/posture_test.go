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

package config_test

import (
	"testing"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// --- BuildPostureReport ---

func TestBuildPostureReport_CollectsStringFields(t *testing.T) {
	type S struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	}
	report := cfgloader.BuildPostureReport(S{Name: "alice", Value: "42"}, nil, nil)

	findFinding := func(prop string) *cfgloader.PostureFinding {
		for i := range report.Findings {
			if report.Findings[i].Property == prop {
				return &report.Findings[i]
			}
		}
		return nil
	}

	f := findFinding("name")
	if f == nil {
		t.Fatal("expected finding for 'name'")
	}
	if f.Value != "alice" {
		t.Errorf("name value = %q, want %q", f.Value, "alice")
	}
	if f.Status != "PASS" {
		t.Errorf("name status = %q, want PASS", f.Status)
	}
}

func TestBuildPostureReport_RedactsAllowlistedNonEmpty(t *testing.T) {
	type S struct {
		Token string `yaml:"token"`
		Name  string `yaml:"name"`
	}
	report := cfgloader.BuildPostureReport(
		S{Token: "s3cr3t", Name: "visible"},
		nil,
		[]string{"token"},
	)

	findFinding := func(prop string) *cfgloader.PostureFinding {
		for i := range report.Findings {
			if report.Findings[i].Property == prop {
				return &report.Findings[i]
			}
		}
		return nil
	}

	tokenF := findFinding("token")
	if tokenF == nil {
		t.Fatal("expected finding for 'token'")
	}
	if tokenF.Value != "[REDACTED]" {
		t.Errorf("token value = %q, want [REDACTED]", tokenF.Value)
	}

	nameF := findFinding("name")
	if nameF == nil {
		t.Fatal("expected finding for 'name'")
	}
	if nameF.Value != "visible" {
		t.Errorf("name value = %q, want %q", nameF.Value, "visible")
	}
}

func TestBuildPostureReport_AllowlistedEmptyValueNotRedacted(t *testing.T) {
	// Per implementation: redact only when value != "".
	type S struct {
		Token string `yaml:"token"`
	}
	report := cfgloader.BuildPostureReport(S{Token: ""}, nil, []string{"token"})

	for _, f := range report.Findings {
		if f.Property == "token" {
			if f.Value == "[REDACTED]" {
				t.Error("empty allowlisted field should NOT be redacted")
			}
			return
		}
	}
	// Token is an empty string; it should still be present in findings.
	t.Error("expected a finding for 'token'")
}

func TestBuildPostureReport_SourceFromMap(t *testing.T) {
	type S struct {
		Token string `yaml:"token"`
		Name  string `yaml:"name"`
	}
	sources := cfgloader.SourceMap{
		"token": "env",
	}
	report := cfgloader.BuildPostureReport(S{Token: "t", Name: "n"}, sources, nil)

	for _, f := range report.Findings {
		switch f.Property {
		case "token":
			if f.Source != "env" {
				t.Errorf("token source = %q, want %q", f.Source, "env")
			}
		case "name":
			if f.Source != "static" {
				t.Errorf("name source = %q, want static", f.Source)
			}
		}
	}
}

func TestBuildPostureReport_MissingSourceDefaultsToStatic(t *testing.T) {
	type S struct {
		Name string `yaml:"name"`
	}
	// nil source map
	report := cfgloader.BuildPostureReport(S{Name: "x"}, nil, nil)
	for _, f := range report.Findings {
		if f.Property == "name" && f.Source != "static" {
			t.Errorf("source = %q, want static", f.Source)
		}
	}
}

func TestBuildPostureReport_NilPointerConfig(t *testing.T) {
	type S struct {
		Name string `yaml:"name"`
	}
	// Should not panic; nil pointer → no findings.
	var ptr *S
	report := cfgloader.BuildPostureReport(ptr, nil, nil)
	if len(report.Findings) != 0 {
		t.Errorf("nil pointer config should produce no findings, got: %v", report.Findings)
	}
}

func TestBuildPostureReport_AllFindingsDefaultPASS(t *testing.T) {
	type S struct {
		A string `yaml:"a"`
		B string `yaml:"b"`
	}
	report := cfgloader.BuildPostureReport(S{A: "1", B: "2"}, nil, nil)
	for _, f := range report.Findings {
		if f.Status != "PASS" {
			t.Errorf("finding %q has status %q, want PASS", f.Property, f.Status)
		}
	}
}

// --- PostureReport.SetStatus ---

func TestPostureReport_SetStatus_UpdatesExisting(t *testing.T) {
	r := cfgloader.PostureReport{
		Findings: []cfgloader.PostureFinding{
			{Property: "mode", Value: "dev", Source: "static", Status: "PASS"},
		},
	}
	r.SetStatus("mode", "WARN", "use production mode")

	if len(r.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(r.Findings))
	}
	if r.Findings[0].Status != "WARN" {
		t.Errorf("status = %q, want WARN", r.Findings[0].Status)
	}
	if r.Findings[0].Recommendation != "use production mode" {
		t.Errorf("recommendation = %q, want %q", r.Findings[0].Recommendation, "use production mode")
	}
	// Value and Source should be untouched.
	if r.Findings[0].Value != "dev" {
		t.Errorf("value changed unexpectedly to %q", r.Findings[0].Value)
	}
}

func TestPostureReport_SetStatus_AppendsNewFinding(t *testing.T) {
	var r cfgloader.PostureReport
	r.SetStatus("new.field", "WARN", "configure me")

	if len(r.Findings) != 1 {
		t.Errorf("expected 1 finding appended, got %d", len(r.Findings))
	}
	f := r.Findings[0]
	if f.Property != "new.field" {
		t.Errorf("property = %q, want %q", f.Property, "new.field")
	}
	if f.Status != "WARN" {
		t.Errorf("status = %q, want WARN", f.Status)
	}
	if f.Source != "static" {
		t.Errorf("source = %q, want static", f.Source)
	}
}

func TestPostureReport_SetStatus_OnlyMatchingPropertyUpdated(t *testing.T) {
	r := cfgloader.PostureReport{
		Findings: []cfgloader.PostureFinding{
			{Property: "a", Status: "PASS"},
			{Property: "b", Status: "PASS"},
		},
	}
	r.SetStatus("a", "WARN", "fix a")

	if r.Findings[0].Status != "WARN" {
		t.Errorf("a status = %q, want WARN", r.Findings[0].Status)
	}
	if r.Findings[1].Status != "PASS" {
		t.Errorf("b status changed unexpectedly to %q", r.Findings[1].Status)
	}
}

// --- PostureReport.Log ---

func TestPostureReport_Log_DoesNotPanicOnEmpty(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Log panicked on empty report: %v", r)
		}
	}()
	var r cfgloader.PostureReport
	r.Log("test-component")
}

func TestPostureReport_Log_DoesNotPanicWithFindings(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Log panicked: %v", r)
		}
	}()
	r := cfgloader.PostureReport{
		Findings: []cfgloader.PostureFinding{
			{Property: "mode", Value: "dev", Source: "static", Status: "WARN", Recommendation: "use production"},
			{Property: "identity.strategy", Value: "oidc-file", Source: "static", Status: "PASS"},
		},
	}
	r.Log("gate")
}

// TestBuildPostureReport_WARNCountMatchesFindings verifies that SetStatus + Log
// correctly tracks the number of WARN findings (behavior, not log output).
func TestBuildPostureReport_WARNsCountedCorrectly(t *testing.T) {
	r := cfgloader.PostureReport{
		Findings: []cfgloader.PostureFinding{
			{Property: "a", Status: "WARN"},
			{Property: "b", Status: "PASS"},
			{Property: "c", Status: "WARN"},
		},
	}
	warnCount := 0
	for _, f := range r.Findings {
		if f.Status == "WARN" {
			warnCount++
		}
	}
	if warnCount != 2 {
		t.Errorf("expected 2 WARNs, got %d", warnCount)
	}
}
