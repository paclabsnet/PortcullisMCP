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
	"fmt"
	"io"
	"os"
	"sync/atomic"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	"gopkg.in/natefinch/lumberjack.v2"
)

// ActivitySink is the interface for writing serialized JSON-lines records.
// Implementations must be safe for single-goroutine use (the worker calls
// Write sequentially; no concurrent calls are made).
type ActivitySink interface {
	Write(line []byte) error
	Close() error
}

// newSink constructs the appropriate ActivitySink for the given config.
// For remote sinks ("http", "otlp"), no local files are created and the
// zero-disk mandate is strictly enforced — errors return a nil sink (noop),
// never fall back to file logging.
func newSink(cfg cfgloader.MCPActivityLogConfig) (ActivitySink, error) {
	switch cfg.Sink {
	case "http":
		return NewHTTPBatchSink(cfg.HTTP)
	case "otlp":
		return NewOTLPSink(cfg.OTLP)
	case "stdout":
		return &stdoutSink{}, nil
	case "file", "":
		// Legacy back-compat: "file" was formerly signalled by File=="stdout".
		if cfg.File == "stdout" {
			return &stdoutSink{}, nil
		}
		if cfg.File == "" {
			return nil, fmt.Errorf("activitylog: file path is empty")
		}
		return &fileSink{
			lj: &lumberjack.Logger{
				Filename:   cfg.File,
				MaxSize:    cfg.MaxSizeMB,
				MaxBackups: cfg.MaxBackups,
				MaxAge:     cfg.MaxAgeDays,
				Compress:   cfg.Compress,
			},
		}, nil
	default:
		return nil, fmt.Errorf("activitylog: unknown sink type %q", cfg.Sink)
	}
}

// fileSink writes JSON-lines records to a lumberjack rotating file.
// It implements StatsSink to expose exported_entries counts to Prometheus.
type fileSink struct {
	lj            io.WriteCloser
	exportedCount atomic.Int64
}

func (s *fileSink) Write(line []byte) error {
	_, err := s.lj.Write(line)
	if err == nil {
		s.exportedCount.Add(1)
	}
	return err
}

func (s *fileSink) Close() error {
	return s.lj.Close()
}

func (s *fileSink) Stats() map[string]any {
	return map[string]any{
		"exported_entries": s.exportedCount.Load(),
	}
}

// stdoutSink writes JSON-lines records to os.Stdout.
// Suitable for containerised deployments where a sidecar collector reads stdout.
// It implements StatsSink to expose exported_entries counts to Prometheus.
type stdoutSink struct {
	exportedCount atomic.Int64
}

func (s *stdoutSink) Write(line []byte) error {
	_, err := os.Stdout.Write(line)
	if err == nil {
		s.exportedCount.Add(1)
	}
	return err
}

func (s *stdoutSink) Close() error { return nil }

func (s *stdoutSink) Stats() map[string]any {
	return map[string]any{
		"exported_entries": s.exportedCount.Load(),
	}
}
