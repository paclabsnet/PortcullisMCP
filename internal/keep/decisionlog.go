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

package keep

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// DecisionLogEntry represents a single policy decision log entry.
type DecisionLogEntry struct {
	Timestamp  time.Time      `json:"timestamp"`
	SessionID  string         `json:"session_id"`
	TraceID    string         `json:"trace_id"`
	UserID     string         `json:"user_id"`
	ServerName string         `json:"server_name,omitempty"`
	ToolName   string         `json:"tool_name"`
	Decision   string         `json:"decision"` // "allow" | "deny" | "escalate"
	Reason     string         `json:"reason,omitempty"`
	PDPRequestID string       `json:"pdp_request_id,omitempty"` // reference ID echoed by the PDP, if any
	Source     string         `json:"source"`             // "gate-fastpath" | "pdp"
	Arguments  map[string]any `json:"arguments,omitempty"`
	Result     string         `json:"result,omitempty"` // summary of tool result
}

// DecisionLogger manages decision log entries and dispatches them to configured sinks.
// It uses a channel-based architecture where log entries are sent to a buffered channel,
// and a background worker goroutine receives from the channel, batches entries, and
// writes them to the remote endpoint at regular intervals.
type DecisionLogger struct {
	entryChan     chan *DecisionLogEntry
	bufferSize    int
	cfg           DecisionLogConfig
	client        *http.Client
	done          chan struct{}
	wg            sync.WaitGroup
	shutdownOnce  sync.Once
	flushInterval time.Duration
	maxBatchSize  int
	droppedCount  int64 // Atomic counter for dropped entries
}

// NewDecisionLogger creates a new DecisionLogger instance.
// If cfg.Enabled is false, returns a no-op logger.
func NewDecisionLogger(cfg DecisionLogConfig) *DecisionLogger {
	if !cfg.Enabled {
		return &DecisionLogger{
			entryChan: make(chan *DecisionLogEntry, 1),
			done:      make(chan struct{}),
			cfg:       cfg,
		}
	}

	bufferSize := 10000
	if cfg.BufferSize > 0 {
		bufferSize = cfg.BufferSize
	}

	flushInterval := 5 * time.Second
	if cfg.FlushInterval > 0 {
		flushInterval = time.Duration(cfg.FlushInterval) * time.Second
	}

	maxBatchSize := 1000
	if cfg.MaxBatchSize > 0 {
		maxBatchSize = cfg.MaxBatchSize
	}

	dl := &DecisionLogger{
		entryChan:     make(chan *DecisionLogEntry, bufferSize),
		bufferSize:    bufferSize,
		cfg:           cfg,
		client:        &http.Client{Timeout: 30 * time.Second},
		done:          make(chan struct{}),
		flushInterval: flushInterval,
		maxBatchSize:  maxBatchSize,
		droppedCount:  0,
	}

	// Start background worker
	dl.wg.Add(1)
	go dl.worker()

	slog.Debug("decision logger started",
		"buffer_size", bufferSize,
		"flush_interval", flushInterval,
		"max_batch_size", maxBatchSize,
		"url", cfg.URL)

	return dl
}

// Log adds a decision log entry to the channel.
// If the channel is full, the entry is dropped to prevent blocking.
// This is a non-blocking operation.
func (dl *DecisionLogger) Log(entry *DecisionLogEntry) {
	if entry == nil || !dl.cfg.Enabled {
		return
	}

	// Set timestamp if not already set
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	// Non-blocking send to channel
	select {
	case dl.entryChan <- entry:
		// Successfully sent
	default:
		// Channel full, drop entry
		atomic.AddInt64(&dl.droppedCount, 1)
		slog.Warn("decision log channel full, entry dropped",
			"total_dropped", atomic.LoadInt64(&dl.droppedCount))
	}
}

// worker is the background goroutine that receives entries from the channel,
// batches them, and periodically writes them to the configured endpoint.
func (dl *DecisionLogger) worker() {
	defer dl.wg.Done()

	ticker := time.NewTicker(dl.flushInterval)
	defer ticker.Stop()

	var batch []*DecisionLogEntry

	for {
		select {
		case <-dl.done:
			// Drain any remaining entries from channel and flush
			dl.drainChannelAndFlush(&batch)
			return

		case entry := <-dl.entryChan:
			// Accumulate entry in batch
			batch = append(batch, entry)

			// If batch reaches max size, flush immediately
			if len(batch) >= dl.maxBatchSize {
				dl.flushBatch(batch)
				batch = batch[:0] // Clear batch
			}

		case <-ticker.C:
			// Periodic flush
			if len(batch) > 0 {
				dl.flushBatch(batch)
				batch = batch[:0] // Clear batch
			}
		}
	}
}

// drainChannelAndFlush drains any remaining entries from the channel and flushes them.
// This is called during shutdown to ensure no entries are lost.
func (dl *DecisionLogger) drainChannelAndFlush(batch *[]*DecisionLogEntry) {
	// Drain channel
	for {
		select {
		case entry := <-dl.entryChan:
			*batch = append(*batch, entry)
		default:
			// Channel is empty
			if len(*batch) > 0 {
				dl.flushBatch(*batch)
			}
			return
		}
	}
}

// flushBatch writes a batch of entries to the configured endpoint and optionally console.
func (dl *DecisionLogger) flushBatch(entries []*DecisionLogEntry) {
	if len(entries) == 0 {
		return
	}

	slog.Debug("flushing decision logs", "count", len(entries))

	// Write to console if enabled
	if dl.cfg.Console {
		for _, entry := range entries {
			data, _ := json.Marshal(entry)
			fmt.Println(string(data))
		}
	}

	// Write to remote endpoint if configured
	if dl.cfg.URL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := dl.sendToRemote(ctx, entries); err != nil {
			slog.Error("failed to send decision logs to remote endpoint", "error", err, "count", len(entries))
			// Don't retry - just log the error
		}
	}
}

// sendToRemote sends a batch of entries to the remote endpoint as gzipped JSON.
func (dl *DecisionLogger) sendToRemote(ctx context.Context, entries []*DecisionLogEntry) error {
	// Marshal entries to JSON
	jsonData, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal entries: %w", err)
	}

	// Compress with gzip
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	if _, err := gzipWriter.Write(jsonData); err != nil {
		return fmt.Errorf("gzip data: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dl.cfg.URL, &buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	for key, value := range dl.cfg.Headers {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := dl.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("remote endpoint returned status %d", resp.StatusCode)
	}

	return nil
}

// Shutdown gracefully shuts down the decision logger.
// It is safe to call Shutdown more than once.
func (dl *DecisionLogger) Shutdown() error {
	if !dl.cfg.Enabled {
		return nil
	}

	dl.shutdownOnce.Do(func() {
		slog.Debug("shutting down decision logger")
		close(dl.done)
		dl.wg.Wait()
		close(dl.entryChan)
	})

	// Close HTTP client
	dl.client.CloseIdleConnections()

	dropped := atomic.LoadInt64(&dl.droppedCount)
	if dropped > 0 {
		slog.Warn("decision logger shutdown complete with dropped entries",
			"total_dropped", dropped)
	} else {
		slog.Debug("decision logger shutdown complete")
	}

	return nil
}

// Stats returns statistics about the decision logger.
func (dl *DecisionLogger) Stats() map[string]interface{} {
	if !dl.cfg.Enabled {
		return map[string]interface{}{"enabled": false}
	}

	return map[string]interface{}{
		"enabled":        true,
		"channel_length": len(dl.entryChan),
		"channel_cap":    cap(dl.entryChan),
		"dropped_count":  atomic.LoadInt64(&dl.droppedCount),
		"flush_interval": dl.flushInterval.String(),
		"max_batch_size": dl.maxBatchSize,
		"url":            dl.cfg.URL,
		"console":        dl.cfg.Console,
	}
}
