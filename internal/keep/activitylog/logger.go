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

// Package activitylog provides an asynchronous, bounded-memory activity log for
// MCP tool call audit records. It writes correlated mcp_request and mcp_response
// JSON-lines to a rotating file or stdout via a single background worker goroutine,
// guaranteeing FIFO record ordering.
//
// The hot path (LogRequest / LogResponse) is entirely lock-free: if the in-memory
// channel is full, events are dropped and counted atomically rather than blocking
// tool execution. The channel is never closed, making concurrent or straggling
// producers panic-free.
package activitylog

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// dropWarnInterval controls how often a warning is emitted when the channel is
// full: once on the first drop, then once every dropWarnInterval drops.
const dropWarnInterval = 1000

// entryKind identifies the type of a queued log entry.
type entryKind int

const (
	kindRequest   entryKind = iota
	kindResponse
	kindMalformed
)

// logEntry is the internal union type queued on the buffered channel.
type logEntry struct {
	kind entryKind
	data any
}

// RequestEntry is the data provided by Keep for an mcp_request log event.
type RequestEntry struct {
	SessionID   string
	TraceID     string
	RemoteAddr  string
	UserID      string
	Agent       shared.AgentInfo
	ServerName  string
	ToolName    string
	Arguments   map[string]any
	// PDPDecision is the PDP verdict ("allow", "deny", "escalate", "workflow", "error").
	// Included in the record only when IncludePDPDecision is true; omitted otherwise.
	PDPDecision string
	PDPReason   string
	// EscalationJTIs contains the JWT IDs of all escalation tokens presented on a
	// retry request (after approval). Logging all tokens rather than one allows
	// an analyst to join this request with any of the escalation_pending responses
	// that issued them, and to reconstruct multi-step approval chains.
	EscalationJTIs []string
}

// ResponseEntry is the data provided by Keep for an mcp_response log event.
type ResponseEntry struct {
	SessionID  string
	TraceID    string
	RemoteAddr string
	UserID     string
	Agent      shared.AgentInfo
	ServerName string
	ToolName   string
	DurationMS int64
	// Status is one of: "success", "tool_error", "denied", "escalation_pending",
	// "workflow_pending", "backend_error", "auth_error".
	Status string
	// Result is the raw tool result; passed to json.Marshal. Nil means no result field.
	Result any
	// Error is the human-readable error message for non-success statuses.
	Error string
	// EscalationJTI is the JWT ID issued when an escalation or workflow approval
	// is pending. Set on escalation_pending and workflow_pending responses so that
	// the initial request log entry can be joined with the later retry entry.
	EscalationJTI string
	// WorkflowReference is the external ticket or task identifier returned by the
	// workflow system (e.g. a ServiceNow change number). Present on
	// escalation_pending and workflow_pending responses; empty when no workflow
	// system is configured.
	WorkflowReference string
}

// MalformedEntry is the data for an mcp_malformed_request event.
type MalformedEntry struct {
	RemoteAddr string
	TraceID    string
	Error      string
	RawPreview string
}

// requestRecord is the JSON-lines structure written for mcp_request events.
type requestRecord struct {
	Timestamp      time.Time         `json:"timestamp"`
	Event          string            `json:"event"`
	SessionID      string            `json:"session_id,omitempty"`
	TraceID        string            `json:"trace_id,omitempty"`
	RemoteAddr     string            `json:"remote_addr,omitempty"`
	UserID         string            `json:"user_id,omitempty"`
	Agent          *shared.AgentInfo `json:"agent,omitempty"`
	ServerName     string            `json:"server_name,omitempty"`
	ToolName       string            `json:"tool_name,omitempty"`
	Arguments      any               `json:"arguments,omitempty"`
	PDPDecision    string            `json:"pdp_decision,omitempty"`
	PDPReason      string            `json:"pdp_reason,omitempty"`
	EscalationJTIs []string          `json:"escalation_jtis,omitempty"`
}

// responseRecord is the JSON-lines structure written for mcp_response events.
type responseRecord struct {
	Timestamp     time.Time         `json:"timestamp"`
	Event         string            `json:"event"`
	SessionID     string            `json:"session_id,omitempty"`
	TraceID       string            `json:"trace_id,omitempty"`
	RemoteAddr    string            `json:"remote_addr,omitempty"`
	UserID        string            `json:"user_id,omitempty"`
	Agent         *shared.AgentInfo `json:"agent,omitempty"`
	ServerName    string            `json:"server_name,omitempty"`
	ToolName      string            `json:"tool_name,omitempty"`
	DurationMS        int64             `json:"duration_ms"`
	Status            string            `json:"status,omitempty"`
	Result            any               `json:"result,omitempty"`
	Error             string            `json:"error,omitempty"`
	EscalationJTI     string            `json:"escalation_jti,omitempty"`
	WorkflowReference string            `json:"workflow_reference,omitempty"`
}

// malformedRecord is the JSON-lines structure written for mcp_malformed_request events.
type malformedRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	Event      string    `json:"event"`
	RemoteAddr string    `json:"remote_addr,omitempty"`
	TraceID    string    `json:"trace_id,omitempty"`
	Error      string    `json:"error,omitempty"`
	RawPreview string    `json:"raw_preview,omitempty"`
}

// ActivityLogger is the core audit log engine. It accepts structured event entries,
// queues them on a bounded in-memory channel, and drains them in a single background
// goroutine, guaranteeing FIFO ordering in the output file.
type ActivityLogger struct {
	cfg          cfgloader.MCPActivityLogConfig
	ch           chan logEntry
	stopWorker   chan struct{}
	workerDone   chan struct{}
	closed       atomic.Bool
	droppedCount atomic.Int64
	shutdownOnce sync.Once
	sink         ActivitySink
}

// New creates an ActivityLogger and starts the background worker.
// Returns an error if the underlying ActivitySink cannot be initialised
// (e.g. the configured log file directory does not exist).
func New(cfg cfgloader.MCPActivityLogConfig) (*ActivityLogger, error) {
	sink, err := newSink(cfg)
	if err != nil {
		return nil, err
	}
	return NewWithSink(cfg, sink), nil
}

// NewWithSink creates an ActivityLogger backed by the provided sink and starts
// the background worker. It is intended for testing.
func NewWithSink(cfg cfgloader.MCPActivityLogConfig, sink ActivitySink) *ActivityLogger {
	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = cfgloader.DefaultBufferSize
	}
	al := &ActivityLogger{
		cfg:        cfg,
		ch:         make(chan logEntry, bufSize),
		stopWorker: make(chan struct{}),
		workerDone: make(chan struct{}),
		sink:       sink,
	}
	go al.worker()
	return al
}

// LogRequest enqueues an mcp_request record. Non-blocking: if the channel is at
// capacity the record is dropped and the dropped counter is incremented.
// The record is fully built (including payload truncation) before enqueue so
// that queued entries never hold full untruncated payloads.
func (al *ActivityLogger) LogRequest(entry RequestEntry) {
	al.enqueue(logEntry{kind: kindRequest, data: al.buildRequestRecord(entry)})
}

// LogResponse enqueues an mcp_response record. Non-blocking: same drop policy as LogRequest.
// The record is fully built (including payload truncation) before enqueue.
func (al *ActivityLogger) LogResponse(entry ResponseEntry) {
	al.enqueue(logEntry{kind: kindResponse, data: al.buildResponseRecord(entry)})
}

// LogMalformed enqueues an mcp_malformed_request record. Non-blocking.
// The record is fully built (including raw-preview capping) before enqueue.
func (al *ActivityLogger) LogMalformed(entry MalformedEntry) {
	al.enqueue(logEntry{kind: kindMalformed, data: al.buildMalformedRecord(entry)})
}

func (al *ActivityLogger) enqueue(e logEntry) {
	// After Shutdown is called, al.closed is set and producers simply drop.
	// al.ch is NEVER closed — producers can never panic on send.
	if al.closed.Load() {
		al.droppedCount.Add(1)
		return
	}
	select {
	case al.ch <- e:
	default:
		dropped := al.droppedCount.Add(1)
		// Log a warning at the first drop and then every dropWarnInterval drops
		// to avoid flooding slog during sustained buffer pressure.
		if dropped == 1 || dropped%dropWarnInterval == 0 {
			slog.Warn("activitylog: buffer full, events dropped",
				"total_dropped", dropped)
		}
	}
}

// Shutdown signals the worker to drain buffered entries and close the sink.
// The caller's context deadline governs how long the drain may take.
// Returns ctx.Err() if the context expires before the drain completes.
//
// Shutdown is idempotent: concurrent or repeated calls are safe.
func (al *ActivityLogger) Shutdown(ctx context.Context) error {
	var shutdownErr error
	al.shutdownOnce.Do(func() {
		// Step 1: mark closed so new enqueue calls drop immediately.
		al.closed.Store(true)
		// Step 2: signal the worker to drain and exit.
		close(al.stopWorker)
		// Step 3: wait for the worker to finish draining, bounded by ctx.
		select {
		case <-al.workerDone:
		case <-ctx.Done():
			shutdownErr = ctx.Err()
		}
		// Step 4: report dropped count at shutdown.
		if d := al.droppedCount.Load(); d > 0 {
			slog.Warn("activitylog: shutdown complete with dropped events",
				"total_dropped", d)
		}
	})
	return shutdownErr
}

// DroppedCount returns the total number of events dropped due to buffer overflow
// or post-shutdown arrival.
func (al *ActivityLogger) DroppedCount() int64 {
	return al.droppedCount.Load()
}

// worker is the single background goroutine that serialises and writes log entries.
// FIFO ordering is guaranteed because this is the only reader of al.ch.
func (al *ActivityLogger) worker() {
	defer close(al.workerDone)
	for {
		select {
		case entry := <-al.ch:
			al.writeEntry(entry)
		case <-al.stopWorker:
			// Drain any entries that were enqueued before al.closed was set.
			for {
				select {
				case entry := <-al.ch:
					al.writeEntry(entry)
				default:
					if err := al.sink.Close(); err != nil {
						slog.Warn("activitylog: sink close error", "error", err)
					}
					return
				}
			}
		}
	}
}

func (al *ActivityLogger) writeEntry(e logEntry) {
	var record any
	switch e.kind {
	case kindRequest:
		record = e.data.(requestRecord)
	case kindResponse:
		record = e.data.(responseRecord)
	case kindMalformed:
		record = e.data.(malformedRecord)
	default:
		return
	}

	data, err := json.Marshal(record)
	if err != nil {
		slog.Warn("activitylog: marshal failed", "error", err)
		al.droppedCount.Add(1)
		return
	}
	data = append(data, '\n')
	if err := al.sink.Write(data); err != nil {
		slog.Warn("activitylog: sink write failed", "error", err)
		al.droppedCount.Add(1)
	}
}

func (al *ActivityLogger) buildRequestRecord(e RequestEntry) requestRecord {
	r := requestRecord{
		Timestamp:  time.Now().UTC(),
		Event:      "mcp_request",
		SessionID:  e.SessionID,
		TraceID:    e.TraceID,
		RemoteAddr: e.RemoteAddr,
		UserID:     e.UserID,
		ServerName: e.ServerName,
		ToolName:   e.ToolName,
	}

	if e.Agent.Name != "" || e.Agent.Version != "" {
		agent := e.Agent
		r.Agent = &agent
	}

	if al.cfg.TruncatePayloads && e.Arguments != nil {
		r.Arguments = maybeTruncate(e.Arguments, al.cfg.MaxPayloadBytes)
	} else {
		r.Arguments = e.Arguments
	}

	if al.cfg.IncludePDPDecision {
		r.PDPDecision = e.PDPDecision
		r.PDPReason = e.PDPReason
	}

	if len(e.EscalationJTIs) > 0 {
		r.EscalationJTIs = append([]string(nil), e.EscalationJTIs...)
	}

	return r
}

func (al *ActivityLogger) buildResponseRecord(e ResponseEntry) responseRecord {
	r := responseRecord{
		Timestamp:  time.Now().UTC(),
		Event:      "mcp_response",
		SessionID:  e.SessionID,
		TraceID:    e.TraceID,
		RemoteAddr: e.RemoteAddr,
		UserID:     e.UserID,
		ServerName: e.ServerName,
		ToolName:   e.ToolName,
		DurationMS: e.DurationMS,
		Status:     e.Status,
		Error:      e.Error,
	}

	if e.Agent.Name != "" || e.Agent.Version != "" {
		agent := e.Agent
		r.Agent = &agent
	}

	if e.Result != nil {
		if al.cfg.TruncatePayloads {
			r.Result = maybeTruncate(e.Result, al.cfg.MaxPayloadBytes)
		} else {
			r.Result = e.Result
		}
	}

	r.EscalationJTI = e.EscalationJTI
	r.WorkflowReference = e.WorkflowReference

	return r
}

func (al *ActivityLogger) buildMalformedRecord(e MalformedEntry) malformedRecord {
	preview := e.RawPreview
	// Cap raw_preview to MaxPayloadBytes (or the default safety limit) to prevent
	// a subverted agent from writing arbitrary-length data to the audit log.
	cap := al.cfg.MaxPayloadBytes
	if cap <= 0 {
		cap = cfgloader.DefaultMaxPayloadBytes
	}
	if len(preview) > cap {
		preview = truncateUTF8(preview, cap)
	}
	return malformedRecord{
		Timestamp:  time.Now().UTC(),
		Event:      "mcp_malformed_request",
		RemoteAddr: e.RemoteAddr,
		TraceID:    e.TraceID,
		Error:      e.Error,
		RawPreview: preview,
	}
}
