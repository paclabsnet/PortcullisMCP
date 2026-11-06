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

package activitylog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// OTLPSink delivers activity log entries to an OpenTelemetry Collector's
// OTLP/HTTP logs endpoint, formatted as ExportLogsServiceRequest JSON.
//
// Each JSON-line entry produced by ActivityLogger is embedded verbatim in
// logRecords[].body.stringValue. Structured fields (trace_id, event, tool_name,
// user_id, etc.) are also extracted and placed in logRecords[].attributes so
// that OTel Collectors and downstream backends can filter without parsing body.
type OTLPSink struct {
	*networkSinkBase
	cfg        cfgloader.OTLPActivitySinkConfig
	httpClient *http.Client
}

// NewOTLPSink constructs and starts an OTLPSink.
// Returns an error if the TLS configuration is invalid.
func NewOTLPSink(cfg cfgloader.OTLPActivitySinkConfig) (*OTLPSink, error) {
	tlsCfg, err := buildTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("otlp sink: %w", err)
	}
	transport := &http.Transport{}
	if tlsCfg != nil {
		transport.TLSClientConfig = tlsCfg
	}
	s := &OTLPSink{
		cfg:        cfg,
		httpClient: newSinkHTTPClient(transport),
	}
	s.networkSinkBase = newNetworkSinkBase(batchNetworkConfig{
		batchSize:        cfg.BatchSize,
		maxQueuedBatches: cfg.MaxQueuedBatches,
		flushIntervalMS:  cfg.FlushIntervalMS,
		timeoutMS:        cfg.TimeoutMS,
		maxRetries:       cfg.MaxRetries,
		retryBackoffMS:   cfg.RetryBackoffMS,
	}, s.post)
	return s, nil
}

// Write implements ActivitySink.
func (s *OTLPSink) Write(line []byte) error {
	return s.networkSinkBase.Write(line)
}

// Close implements ActivitySink.
func (s *OTLPSink) Close() error {
	return s.networkSinkBase.Close()
}

// Stats returns diagnostic counters for this sink.
func (s *OTLPSink) Stats() map[string]any {
	return s.networkSinkBase.sinkStats()
}

// otlpEntry contains the fields extracted from a JSON-lines activity record for
// constructing a structured OTLP log record.
type otlpEntry struct {
	Timestamp  string `json:"timestamp"`
	Event      string `json:"event"`
	TraceID    string `json:"trace_id"`
	UserID     string `json:"user_id"`
	ToolName   string `json:"tool_name"`
	ServerName string `json:"server_name"`
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	Agent      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"agent"`
}

// otlpSeverity returns the OTLP severity number and text for an activity event.
// OTLP severity numbers: INFO=9, WARN=13, ERROR=17.
func otlpSeverity(event, status string) (int, string) {
	switch status {
	case "denied", "escalation_pending", "workflow_pending":
		return 13, "WARN"
	case "backend_error", "auth_error", "tool_error":
		return 17, "ERROR"
	}
	switch event {
	case "mcp_malformed_request":
		return 17, "ERROR"
	}
	return 9, "INFO"
}

// formatTraceID converts a trace_id to the 32-char lowercase hex format required
// by OTLP. If the input is a standard 36-char hyphenated UUID, hyphens are stripped.
// Returns ("", rawID) if the result is not valid 32-char hex, so the caller can
// fall back to adding it as an attribute instead.
func formatTraceID(raw string) (traceHex, fallback string) {
	if raw == "" {
		return "", ""
	}
	// Strip hyphens from UUID form.
	candidate := strings.ReplaceAll(raw, "-", "")
	if len(candidate) != 32 {
		return "", raw
	}
	for _, r := range candidate {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return "", raw
		}
	}
	return strings.ToLower(candidate), ""
}

// otlpKV builds an OTLP keyValue attribute object.
func otlpKV(key, value string) map[string]any {
	return map[string]any{
		"key":   key,
		"value": map[string]any{"stringValue": value},
	}
}

// buildLogRecord constructs a single OTLP logRecord from a raw JSON-lines entry.
func buildLogRecord(line []byte) map[string]any {
	var entry otlpEntry
	_ = json.Unmarshal(line, &entry) // best effort; missing fields → zero values

	// Timestamp
	var timeUnixNano int64
	if entry.Timestamp != "" {
		if ts, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err == nil {
			timeUnixNano = ts.UnixNano()
		}
	}
	if timeUnixNano == 0 {
		timeUnixNano = time.Now().UnixNano()
	}
	nanoStr := fmt.Sprintf("%d", timeUnixNano)

	sevNum, sevText := otlpSeverity(entry.Event, entry.Status)

	// Trace ID
	traceHex, traceIDFallback := formatTraceID(entry.TraceID)

	// Structured attributes
	attrs := make([]map[string]any, 0, 8)
	if entry.Event != "" {
		attrs = append(attrs, otlpKV("event.type", entry.Event))
	}
	if entry.ToolName != "" {
		attrs = append(attrs, otlpKV("mcp.tool_name", entry.ToolName))
	}
	if entry.ServerName != "" {
		attrs = append(attrs, otlpKV("mcp.server_name", entry.ServerName))
	}
	if entry.UserID != "" {
		attrs = append(attrs, otlpKV("user.id", entry.UserID))
	}
	if entry.Agent.Name != "" {
		attrs = append(attrs, otlpKV("mcp.agent.name", entry.Agent.Name))
	}
	if entry.Agent.Version != "" {
		attrs = append(attrs, otlpKV("mcp.agent.version", entry.Agent.Version))
	}
	if entry.Status != "" {
		attrs = append(attrs, otlpKV("mcp.status", entry.Status))
	}
	if entry.DurationMS != 0 {
		attrs = append(attrs, map[string]any{
			"key":   "mcp.duration_ms",
			"value": map[string]any{"intValue": fmt.Sprintf("%d", entry.DurationMS)},
		})
	}
	// If trace_id could not be formatted as 32-char hex, preserve it in attributes.
	if traceIDFallback != "" {
		attrs = append(attrs, otlpKV("mcp.trace_id", traceIDFallback))
	}

	rec := map[string]any{
		"timeUnixNano":         nanoStr,
		"observedTimeUnixNano": nanoStr,
		"severityNumber":       sevNum,
		"severityText":         sevText,
		"body":                 map[string]any{"stringValue": string(line)},
		"attributes":           attrs,
	}
	if traceHex != "" {
		rec["traceId"] = traceHex
	}
	return rec
}

// post serialises one batch as an OTLP ExportLogsServiceRequest and POSTs it.
func (s *OTLPSink) post(ctx context.Context, batch [][]byte) error {
	logRecords := make([]map[string]any, 0, len(batch))
	for _, line := range batch {
		logRecords = append(logRecords, buildLogRecord(line))
	}

	payload := map[string]any{
		"resourceLogs": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []map[string]any{
						{"key": "service.name", "value": map[string]any{"stringValue": "portcullis-keep"}},
						{"key": "telemetry.sdk.language", "value": map[string]any{"stringValue": "go"}},
					},
				},
				"scopeLogs": []map[string]any{
					{
						"scope":      map[string]any{"name": "portcullis.activity_log", "version": "1.0.0"},
						"logRecords": logRecords,
					},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("otlp marshal: %w", err)
	}

	return postHTTP(ctx, s.httpClient, s.cfg.Endpoint, "application/json", body, s.cfg.Auth, s.cfg.Headers)
}
