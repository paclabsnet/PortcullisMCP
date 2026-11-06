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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// batchNetworkConfig holds the tuning parameters shared by all remote network sinks.
type batchNetworkConfig struct {
	batchSize        int
	maxQueuedBatches int
	flushIntervalMS  int
	timeoutMS        int
	maxRetries       int
	retryBackoffMS   int
}

// networkStatusError is returned by a sink's postBatch implementation to signal
// an HTTP status code, letting the dispatcher decide whether to retry.
type networkStatusError struct {
	code int
}

func (e *networkStatusError) Error() string {
	return fmt.Sprintf("HTTP status %d", e.code)
}

// networkSinkBase implements the three-tier bounded-buffer batching and
// dispatch mechanics shared by HTTPBatchSink and OTLPSink.
//
// Tier 1 (al.ch) lives in the caller's ActivityLogger.
// Tier 2 is activeBatch (capacity: batchSize).
// Tier 3 is dispatchCh (capacity: maxQueuedBatches).
//
// None of Write, the ticker loop, or the dispatcher loop ever block waiting
// for each other; overflow is dropped non-blockingly.
type networkSinkBase struct {
	cfg batchNetworkConfig

	// postBatch serialises the batch and delivers it to the remote endpoint.
	// Return nil on success, *networkStatusError for HTTP status failures, or
	// any other error for network/transport failures.
	postBatch func(ctx context.Context, batch [][]byte) error

	mu          sync.Mutex
	activeBatch [][]byte
	dispatchCh  chan [][]byte

	rootCtx    context.Context
	cancelRoot context.CancelFunc
	stopTicker chan struct{}
	tickerDone chan struct{}
	wg         sync.WaitGroup

	exportedEntries atomic.Int64
	droppedBatches  atomic.Int64
	droppedEntries  atomic.Int64
}

// newNetworkSinkBase creates and starts the ticker and dispatcher goroutines.
// postBatch is called by the dispatcher for each ready batch.
func newNetworkSinkBase(cfg batchNetworkConfig, postBatch func(ctx context.Context, batch [][]byte) error) *networkSinkBase {
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	b := &networkSinkBase{
		cfg:        cfg,
		postBatch:  postBatch,
		dispatchCh: make(chan [][]byte, cfg.maxQueuedBatches),
		rootCtx:    rootCtx,
		cancelRoot: cancelRoot,
		stopTicker: make(chan struct{}),
		tickerDone: make(chan struct{}),
	}
	b.wg.Add(1)
	go b.dispatcherLoop()
	go b.tickerLoop()
	return b
}

// Write appends a copy of line to the in-memory batch. If the batch is full
// it is handed off to the dispatcher channel non-blockingly.
func (b *networkSinkBase) Write(line []byte) error {
	cp := make([]byte, len(line))
	copy(cp, line)

	b.mu.Lock()
	b.activeBatch = append(b.activeBatch, cp)
	if len(b.activeBatch) >= b.cfg.batchSize {
		batch := b.detachLocked()
		b.mu.Unlock()
		b.enqueue(batch)
		return nil
	}
	b.mu.Unlock()
	return nil
}

// detachLocked swaps activeBatch for nil and returns the old slice.
// Caller must hold b.mu.
func (b *networkSinkBase) detachLocked() [][]byte {
	batch := b.activeBatch
	b.activeBatch = nil
	return batch
}

// enqueue sends batch to dispatchCh non-blockingly; drops it if the channel is full.
func (b *networkSinkBase) enqueue(batch [][]byte) {
	select {
	case b.dispatchCh <- batch:
	default:
		b.droppedBatches.Add(1)
		b.droppedEntries.Add(int64(len(batch)))
		slog.Warn("remote sink dispatcher queue full; batch dropped", "batch_size", len(batch))
	}
}

// tickerLoop fires every flushIntervalMS to flush any partial batch.
func (b *networkSinkBase) tickerLoop() {
	defer close(b.tickerDone)
	ticker := time.NewTicker(time.Duration(b.cfg.flushIntervalMS) * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-b.stopTicker:
			return
		case <-ticker.C:
			b.mu.Lock()
			if len(b.activeBatch) > 0 {
				batch := b.detachLocked()
				b.mu.Unlock()
				b.enqueue(batch)
			} else {
				b.mu.Unlock()
			}
		}
	}
}

// dispatcherLoop reads ready batches from dispatchCh and delivers them.
func (b *networkSinkBase) dispatcherLoop() {
	defer b.wg.Done()
	for batch := range b.dispatchCh {
		b.deliver(batch)
	}
}

// deliver attempts to send one batch with retries according to the config.
func (b *networkSinkBase) deliver(batch [][]byte) {
	timeout := time.Duration(b.cfg.timeoutMS) * time.Millisecond
	ctx, cancel := context.WithTimeout(b.rootCtx, timeout)
	defer cancel()

	var lastErr error
	for attempt := 0; attempt <= b.cfg.maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(b.cfg.retryBackoffMS) * time.Millisecond)
		}
		err := b.postBatch(ctx, batch)
		if err == nil {
			b.exportedEntries.Add(int64(len(batch)))
			return
		}
		// 4xx responses are non-retryable client errors.
		var statusErr *networkStatusError
		if isNetworkStatusError(err, &statusErr) && statusErr.code/100 == 4 {
			slog.Error("remote sink rejected batch (non-retryable)", "status", statusErr.code, "batch_size", len(batch))
			b.droppedBatches.Add(1)
			b.droppedEntries.Add(int64(len(batch)))
			return
		}
		lastErr = err
		if attempt < b.cfg.maxRetries {
			slog.Warn("remote sink transient error; retrying", "attempt", attempt+1, "error", err)
		}
	}
	slog.Error("remote sink delivery failed; batch dropped", "error", lastErr, "batch_size", len(batch))
	b.droppedBatches.Add(1)
	b.droppedEntries.Add(int64(len(batch)))
}

// isNetworkStatusError checks if err is a *networkStatusError and sets target.
func isNetworkStatusError(err error, target **networkStatusError) bool {
	if e, ok := err.(*networkStatusError); ok {
		*target = e
		return true
	}
	return false
}

// Close gracefully shuts down the sink with a four-step sequence:
//  1. Stop the ticker goroutine (guarantees no more writes to dispatchCh).
//  2. Queue the final partial batch.
//  3. Close dispatchCh so the dispatcher exits after draining it.
//  4. Wait for the dispatcher to finish; cancel the root context if it stalls.
func (b *networkSinkBase) Close() error {
	// Step 1: stop ticker.
	close(b.stopTicker)
	<-b.tickerDone

	// Step 2: flush remaining batch.
	b.mu.Lock()
	if len(b.activeBatch) > 0 {
		batch := b.detachLocked()
		b.mu.Unlock()
		b.enqueue(batch)
	} else {
		b.mu.Unlock()
	}

	// Step 3: close dispatcher input.
	close(b.dispatchCh)

	// Step 4: wait for dispatcher; cancel root context if the timeout_ms budget elapses.
	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()

	timeout := time.Duration(b.cfg.timeoutMS) * time.Millisecond
	select {
	case <-done:
	case <-time.After(timeout):
		b.cancelRoot()
		b.wg.Wait()
	}
	return nil
}

// sinkStats returns diagnostic counters shared by all remote sinks.
func (b *networkSinkBase) sinkStats() map[string]any {
	return map[string]any{
		"exported_entries": b.exportedEntries.Load(),
		"dropped_batches":  b.droppedBatches.Load(),
		"dropped_entries":  b.droppedEntries.Load(),
	}
}

// postHTTP is the shared HTTP delivery step used by all remote activity sinks.
// It builds a POST request for the given url, sets Content-Type, applies auth
// and any custom headers, executes the request using client, drains the response
// body to allow connection reuse, and maps non-2xx status codes into a
// networkStatusError so the dispatcher can apply the correct retry policy.
//
// Callers are responsible for serialising the batch into body and choosing the
// appropriate contentType before calling this function. This keeps serialisation
// logic in each sink while ensuring auth/header handling and response processing
// cannot drift between sink implementations.
func postHTTP(ctx context.Context, client *http.Client, url, contentType string, body []byte,
	auth cfgloader.HTTPActivityAuthConfig, headers map[string]string) error {

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	switch auth.Type {
	case "splunk":
		req.Header.Set("Authorization", "Splunk "+auth.Token)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+auth.Token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP POST: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode/100 == 2 {
		return nil
	}
	return &networkStatusError{code: resp.StatusCode}
}

// noRedirect is an http.Client.CheckRedirect policy that disables all automatic
// redirects. Activity log sinks POST to a fixed configured endpoint; a redirect
// response indicates misconfiguration and must not be silently followed, as doing
// so could forward auth tokens and custom headers to an unintended host.
// Returning http.ErrUseLastResponse causes Do to return the redirect response
// (3xx) unchanged so the caller's status-code check handles it correctly.
func noRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// newSinkHTTPClient builds an http.Client with the given transport and the
// shared no-redirect policy applied.
func newSinkHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport:     transport,
		CheckRedirect: noRedirect,
	}
}

// buildTLSConfig constructs a *tls.Config from an ActivityTLSConfig.
// Returns nil (use system defaults) when no custom CA or InsecureSkipVerify is set.
func buildTLSConfig(cfg cfgloader.ActivityTLSConfig) (*tls.Config, error) {
	if cfg.CACertFile == "" && cfg.CACertPEM == "" && !cfg.InsecureSkipVerify {
		return nil, nil
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec
	}

	var pemData []byte
	if cfg.CACertFile != "" {
		data, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("ca_cert_file: %w", err)
		}
		pemData = append(pemData, data...)
	}
	if cfg.CACertPEM != "" {
		pemData = append(pemData, []byte(cfg.CACertPEM)...)
	}
	if len(pemData) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("failed to parse CA certificate PEM data")
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}
