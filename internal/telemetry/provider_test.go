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
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
)

// resetGlobalProvider restores the noop provider after a test that installs a
// real one, preventing global state from leaking between tests.
func resetGlobalProvider(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
	})
}

func TestTraceIDFromContext_NoSpan(t *testing.T) {
	got := telemetry.TraceIDFromContext(context.Background())
	if got != "" {
		t.Errorf("expected empty string for context with no span, got %q", got)
	}
}

func TestTraceIDFromContext_WithActiveSpan(t *testing.T) {
	resetGlobalProvider(t)

	// Use the SDK (not noop) so the span has a valid, sampled trace ID.
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

func TestSetup_Noop(t *testing.T) {
	resetGlobalProvider(t)

	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{Exporter: "noop"})
	if err != nil {
		t.Fatalf("Setup(noop) returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown() returned error: %v", err)
	}
}

func TestSetup_EmptyExporter(t *testing.T) {
	resetGlobalProvider(t)

	// Empty exporter string is treated the same as "noop".
	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{})
	if err != nil {
		t.Fatalf("Setup(\"\") returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown() returned error: %v", err)
	}
}

func TestSetup_Stdout(t *testing.T) {
	resetGlobalProvider(t)

	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Exporter:    "stdout",
		ServiceName: "portcullis-test",
	})
	if err != nil {
		t.Fatalf("Setup(stdout) returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown() returned error: %v", err)
	}
}

func TestSetup_OTLP(t *testing.T) {
	resetGlobalProvider(t)

	// OTLP exporter needs a valid-looking endpoint to not return a creation error.
	// It doesn't need to actually connect during Setup() itself.
	shutdown, err := telemetry.Setup(context.Background(), telemetry.Config{
		Exporter: "otlp",
		OTLP: telemetry.OTLPConfig{
			Endpoint: "http://localhost:4318",
			Headers:  map[string]string{"X-Test": "Value"},
		},
		ServiceName: "portcullis-otlp-test",
	})
	if err != nil {
		t.Fatalf("Setup(otlp) returned error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown() returned error: %v", err)
	}
}

func TestSetup_UnknownExporter(t *testing.T) {
	_, err := telemetry.Setup(context.Background(), telemetry.Config{Exporter: "influxdb"})
	if err == nil {
		t.Fatal("expected error for unknown exporter, got nil")
	}
	if !strings.Contains(err.Error(), "unknown telemetry exporter") {
		t.Errorf("error = %q, want it to mention unknown telemetry exporter", err.Error())
	}
}
