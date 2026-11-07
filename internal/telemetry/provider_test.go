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

package telemetry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
)

// resetGlobalProviders restores noop providers after a test to prevent leakage.
func resetGlobalProviders(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		otel.SetMeterProvider(metricnoop.NewMeterProvider())
	})
}

func TestTraceIDFromContext_NoSpan(t *testing.T) {
	got := telemetry.TraceIDFromContext(context.Background())
	if got != "" {
		t.Errorf("expected empty string for context with no span, got %q", got)
	}
}

func TestTraceIDFromContext_WithActiveSpan(t *testing.T) {
	resetGlobalProviders(t)

	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	ctx, span := otel.Tracer("test").Start(context.Background(), "test-span")
	defer span.End()

	got := telemetry.TraceIDFromContext(ctx)
	if got == "" {
		t.Fatal("expected non-empty trace ID, got empty string")
	}
	if len(got) != 32 {
		t.Errorf("trace ID length = %d, want 32 hex chars; got %q", len(got), got)
	}
	if strings.TrimLeft(got, "0123456789abcdef") != "" {
		t.Errorf("trace ID %q contains non-hex characters", got)
	}
}

func TestSetup_Noop_MetricsDisabled(t *testing.T) {
	resetGlobalProviders(t)

	f := false
	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Exporter: "noop",
		Metrics:  telemetry.MetricsConfig{Enabled: &f},
	}, false)
	if err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown() returned error: %v", err)
	}

	// MetricsHandler should return 404 when disabled.
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	telemetry.MetricsHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("metrics handler status = %d, want 404 when disabled", rr.Code)
	}
}

func TestSetup_Noop_MetricsEnabled(t *testing.T) {
	resetGlobalProviders(t)

	tr := true
	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Exporter:    "noop",
		ServiceName: "test-keep",
		Metrics:     telemetry.MetricsConfig{Enabled: &tr},
	}, false)
	if err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	// MetricsHandler should return 200 with Prometheus content type.
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	telemetry.MetricsHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("metrics handler status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

func TestSetup_MetricsDefault_True(t *testing.T) {
	resetGlobalProviders(t)

	// Nil Enabled + metricsDefaultOn=true → metrics enabled.
	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{Exporter: "noop"}, true)
	if err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	telemetry.MetricsHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("metrics handler status = %d, want 200 (default on)", rr.Code)
	}
}

func TestSetup_MetricsDefault_False(t *testing.T) {
	resetGlobalProviders(t)

	// Nil Enabled + metricsDefaultOn=false → metrics disabled.
	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{Exporter: "noop"}, false)
	if err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	telemetry.MetricsHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("metrics handler status = %d, want 404 (default off)", rr.Code)
	}
}

func TestSetup_EmptyExporter(t *testing.T) {
	resetGlobalProviders(t)

	// Empty exporter string is treated the same as "noop".
	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{}, false)
	if err != nil {
		t.Fatalf("Setup(\"\") returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown() returned error: %v", err)
	}
}

func TestSetup_Stdout(t *testing.T) {
	resetGlobalProviders(t)

	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Exporter:    "stdout",
		ServiceName: "portcullis-test",
	}, false)
	if err != nil {
		t.Fatalf("Setup(stdout) returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown() returned error: %v", err)
	}
}

func TestSetup_OTLP(t *testing.T) {
	resetGlobalProviders(t)

	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Exporter: "otlp",
		OTLP: telemetry.OTLPConfig{
			Endpoint: "http://localhost:4318",
			Headers:  map[string]string{"X-Test": "Value"},
		},
		ServiceName: "portcullis-otlp-test",
	}, false)
	if err != nil {
		t.Fatalf("Setup(otlp) returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown() returned error: %v", err)
	}
}

func TestSetup_UnknownExporter(t *testing.T) {
	_, err := telemetry.Setup(context.Background(), telemetry.Config{Exporter: "influxdb"}, false)
	if err == nil {
		t.Fatal("expected error for unknown exporter, got nil")
	}
	if !strings.Contains(err.Error(), "unknown telemetry exporter") {
		t.Errorf("error = %q, want it to mention unknown telemetry exporter", err.Error())
	}
}

func TestSetup_StdoutTrace_MetricsEnabled(t *testing.T) {
	resetGlobalProviders(t)

	tr := true
	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Exporter:    "stdout",
		ServiceName: "portcullis-test",
		Metrics:     telemetry.MetricsConfig{Enabled: &tr},
	}, false)
	if err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	// Both trace and metrics active simultaneously.
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	telemetry.MetricsHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("metrics handler status = %d, want 200", rr.Code)
	}
}

func TestMetricsConfig_EffectivePath(t *testing.T) {
	cases := []struct {
		cfg  telemetry.MetricsConfig
		want string
	}{
		{telemetry.MetricsConfig{}, "/metrics"},
		{telemetry.MetricsConfig{Path: "/metrics"}, "/metrics"},
		{telemetry.MetricsConfig{Path: "/custom/metrics"}, "/custom/metrics"},
		{telemetry.MetricsConfig{Path: "metrics"}, "/metrics"},
	}
	for _, tc := range cases {
		got := tc.cfg.EffectivePath()
		if got != tc.want {
			t.Errorf("EffectivePath(%q) = %q, want %q", tc.cfg.Path, got, tc.want)
		}
	}
}

func TestSetup_Twice_NoRegistryConflict(t *testing.T) {
	resetGlobalProviders(t)

	tr := true
	cfg := telemetry.Config{
		Exporter: "noop",
		Metrics:  telemetry.MetricsConfig{Enabled: &tr},
	}
	shutdown1, err := telemetry.Setup(context.Background(), cfg, false)
	if err != nil {
		t.Fatalf("first Setup returned error: %v", err)
	}
	_ = shutdown1(context.Background())

	shutdown2, err := telemetry.Setup(context.Background(), cfg, false)
	if err != nil {
		t.Fatalf("second Setup returned error: %v", err)
	}
	defer func() { _ = shutdown2(context.Background()) }()

	// Second setup should produce a working handler without panic.
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	telemetry.MetricsHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("metrics handler after second setup = %d, want 200", rr.Code)
	}
}

func TestMeter_ReturnsUsableMeter(t *testing.T) {
	resetGlobalProviders(t)

	tr := true
	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Exporter: "noop",
		Metrics:  telemetry.MetricsConfig{Enabled: &tr},
	}, false)
	if err != nil {
		t.Fatalf("Setup returned error: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	meter := telemetry.Meter("test-component")
	counter, err := meter.Int64Counter("test.counter")
	if err != nil {
		t.Fatalf("create counter: %v", err)
	}
	// Should not panic.
	counter.Add(context.Background(), 1)
}
