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
// Returns an error if a file sink cannot be initialised.
func newSink(cfg cfgloader.MCPActivityLogConfig) (ActivitySink, error) {
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
}

// fileSink writes JSON-lines records to a lumberjack rotating file.
type fileSink struct {
	lj io.WriteCloser
}

func (s *fileSink) Write(line []byte) error {
	_, err := s.lj.Write(line)
	return err
}

func (s *fileSink) Close() error {
	return s.lj.Close()
}

// stdoutSink writes JSON-lines records to os.Stdout.
// Suitable for containerised deployments where a sidecar collector reads stdout.
type stdoutSink struct{}

func (s *stdoutSink) Write(line []byte) error {
	_, err := os.Stdout.Write(line)
	return err
}

func (s *stdoutSink) Close() error { return nil }
