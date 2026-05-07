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
	"log/slog"
	"sync"
	"time"
)

// DecisionLogEntry is a decision log entry sent to Keep.
type DecisionLogEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	SessionID string         `json:"session_id"`
	TraceID   string         `json:"trace_id"`
	UserID    string         `json:"user_id"`
	ToolName  string         `json:"tool_name"`
	Decision  string         `json:"decision"` // "allow" | "deny"
	Reason    string         `json:"reason"`
	Source    string         `json:"source"` // "gate-fastpath" | "gate-multitenant"
	Arguments map[string]any `json:"arguments,omitempty"`
}

// DecisionLogger is the interface for asynchronous, batched decision log shipping.
type DecisionLogger interface {
	// Log enqueues a decision log entry. Implementations must be non-blocking.
	Log(entry DecisionLogEntry)
	// Start launches the background worker. ctx cancellation triggers a graceful
	// shutdown with a final flush of any buffered entries.
	Start(ctx context.Context)
}

// BatchDecisionLogger buffers DecisionLogEntry values and ships them to Keep
// in batches, triggered by either a size threshold or a flush interval.
type BatchDecisionLogger struct {
	cfg       DecisionLogBatchConfig
	forwarder KeepForwarder
	ch        chan DecisionLogEntry
	done      chan struct{}
	wg        sync.WaitGroup
}

// NewBatchDecisionLogger creates a BatchDecisionLogger. Call Start to begin processing.
func NewBatchDecisionLogger(cfg DecisionLogBatchConfig, forwarder KeepForwarder) *BatchDecisionLogger {
	return &BatchDecisionLogger{
		cfg:       cfg,
		forwarder: forwarder,
		ch:        make(chan DecisionLogEntry, 1000),
		done:      make(chan struct{}),
	}
}

// Log enqueues entry for batched delivery. Non-blocking: drops the entry if the
// internal buffer is full to avoid slowing down tool calls.
func (l *BatchDecisionLogger) Log(entry DecisionLogEntry) {
	select {
	case l.ch <- entry:
	default:
	}
}

// Start launches the background worker goroutine. When ctx is cancelled the
// worker flushes any remaining entries before exiting. Call Wait to block until
// the final flush completes.
func (l *BatchDecisionLogger) Start(ctx context.Context) {
	l.wg.Add(1)
	go l.worker()
	go func() {
		<-ctx.Done()
		close(l.done)
	}()
}

// Wait blocks until the worker has flushed all remaining entries and exited.
// Useful only after the context passed to Start has been cancelled.
func (l *BatchDecisionLogger) Wait() {
	l.wg.Wait()
}

func (l *BatchDecisionLogger) worker() {
	defer l.wg.Done()

	flushInterval := 30 * time.Second
	if l.cfg.FlushInterval > 0 {
		flushInterval = time.Duration(l.cfg.FlushInterval) * time.Second
	}
	maxBatchSize := 100
	if l.cfg.MaxBatchSize > 0 {
		maxBatchSize = l.cfg.MaxBatchSize
	}

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	var batch []DecisionLogEntry

	for {
		select {
		case <-l.done:
			for {
				select {
				case entry := <-l.ch:
					batch = append(batch, entry)
				default:
					if len(batch) > 0 {
						l.flush(batch)
					}
					return
				}
			}

		case entry := <-l.ch:
			batch = append(batch, entry)
			if len(batch) >= maxBatchSize {
				l.flush(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				l.flush(batch)
				batch = batch[:0]
			}
		}
	}
}

func (l *BatchDecisionLogger) flush(entries []DecisionLogEntry) {
	if len(entries) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.forwarder.SendLogs(ctx, entries); err != nil {
		slog.Warn("failed to send decision logs to keep", "error", err, "count", len(entries))
	} else {
		slog.Debug("sent decision logs to keep", "count", len(entries))
	}
}
