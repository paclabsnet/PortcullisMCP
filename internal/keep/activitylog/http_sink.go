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
	"bytes"
	"context"
	"fmt"
	"net/http"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// HTTPBatchSink delivers activity log entries to an HTTPS ingest endpoint in
// batches. It supports two wire encodings:
//   - "ndjson" (default): newline-delimited JSON lines (Splunk HEC raw, Logstash, Vector).
//   - "json_array": top-level JSON array (Datadog Logs API, OPA format, REST webhooks).
//
// The three-tier bounded buffer and race-free shutdown are implemented by the
// embedded networkSinkBase; HTTPBatchSink only owns serialisation and HTTP delivery.
type HTTPBatchSink struct {
	*networkSinkBase
	cfg        cfgloader.HTTPActivitySinkConfig
	httpClient *http.Client
}

// NewHTTPBatchSink constructs and starts an HTTPBatchSink.
// Returns an error if the TLS configuration is invalid.
func NewHTTPBatchSink(cfg cfgloader.HTTPActivitySinkConfig) (*HTTPBatchSink, error) {
	tlsCfg, err := buildTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("http sink: %w", err)
	}
	transport := &http.Transport{}
	if tlsCfg != nil {
		transport.TLSClientConfig = tlsCfg
	}
	s := &HTTPBatchSink{
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
func (s *HTTPBatchSink) Write(line []byte) error {
	return s.networkSinkBase.Write(line)
}

// Close implements ActivitySink.
func (s *HTTPBatchSink) Close() error {
	return s.networkSinkBase.Close()
}

// Stats returns diagnostic counters for this sink.
func (s *HTTPBatchSink) Stats() map[string]any {
	return s.networkSinkBase.sinkStats()
}

// post serialises one batch and POSTs it to the configured URL.
func (s *HTTPBatchSink) post(ctx context.Context, batch [][]byte) error {
	var body []byte
	var contentType string

	switch s.cfg.Encoding {
	case "json_array":
		body = append([]byte("["), bytes.Join(batch, []byte(","))...)
		body = append(body, ']')
		contentType = "application/json"
	default: // "ndjson"
		body = append(bytes.Join(batch, []byte("\n")), '\n')
		contentType = "application/x-ndjson"
	}

	return postHTTP(ctx, s.httpClient, s.cfg.URL, contentType, body, s.cfg.Auth, s.cfg.Headers)
}
