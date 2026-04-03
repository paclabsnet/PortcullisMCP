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

package config

import (
	"log/slog"
	"reflect"
)

// PostureFinding records a single security property observed at startup.
type PostureFinding struct {
	Property       string // dotted YAML path, e.g. "server.endpoints.main.auth.type"
	Value          string // resolved value, or "[REDACTED]" if in the secret allowlist
	Source         string // "static", "env", "file", or "vault"
	Status         string // "PASS" or "WARN"
	Recommendation string // corrective action; empty for PASS findings
}

// PostureReport holds all findings produced by Config.Validate().
type PostureReport struct {
	Findings []PostureFinding
}

// SetStatus updates the Status and Recommendation of the finding at property.
// If no finding with that property exists, a new finding is appended.
func (r *PostureReport) SetStatus(property, status, recommendation string) {
	for i, f := range r.Findings {
		if f.Property == property {
			r.Findings[i].Status = status
			r.Findings[i].Recommendation = recommendation
			return
		}
	}
	r.Findings = append(r.Findings, PostureFinding{
		Property:       property,
		Source:         "static",
		Status:         status,
		Recommendation: recommendation,
	})
}

// Log emits a structured SIEM-compatible log for the entire report.
// Call this after SetupLogging so output uses the configured format and level.
// WARN-status findings are logged at Warn level; all others at Info level.
func (r PostureReport) Log(component string) {
	warnCount := 0
	for _, f := range r.Findings {
		if f.Status == "WARN" {
			warnCount++
		}
	}
	slog.Info("security posture attestation",
		"event_type", "security_posture_attestation",
		"component", component,
		"total_findings", len(r.Findings),
		"warnings", warnCount,
	)
	for _, f := range r.Findings {
		attrs := []any{
			"event_type", "security_posture_attestation",
			"component", component,
			"property", f.Property,
			"value", f.Value,
			"source", f.Source,
			"status", f.Status,
		}
		if f.Recommendation != "" {
			attrs = append(attrs, "recommendation", f.Recommendation)
		}
		if f.Status == "WARN" {
			slog.Warn("assessment finding", attrs...)
		} else {
			slog.Info("assessment finding", attrs...)
		}
	}
}

// BuildPostureReport walks cfg using reflection and collects all string fields
// as findings. Fields present in allowlist are redacted. Sources are populated
// from the provided SourceMap; fields absent from the map default to "static".
func BuildPostureReport(cfg any, sources SourceMap, allowlist []string) PostureReport {
	redact := make(map[string]bool, len(allowlist))
	for _, p := range allowlist {
		redact[p] = true
	}

	var report PostureReport
	v := reflect.ValueOf(cfg)
	_ = Walk(v, "", func(path, value string) error {
		source := sources[path]
		if source == "" {
			source = "static"
		}
		displayValue := value
		if redact[path] && value != "" {
			displayValue = "[REDACTED]"
		}
		report.Findings = append(report.Findings, PostureFinding{
			Property: path,
			Value:    displayValue,
			Source:   source,
			Status:   "PASS",
		})
		return nil
	})
	return report
}
