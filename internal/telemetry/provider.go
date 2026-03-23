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

// Package telemetry provides OpenTelemetry provider setup shared by
// portcullis-gate and portcullis-keep.
package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config configures OpenTelemetry tracing for a Portcullis component.
type Config struct {
	// Exporter selects the trace exporter: "otlp", "stdout", or "noop" (default).
	Exporter    string     `yaml:"exporter"`
	ServiceName string     `yaml:"service_name"`
	OTLP        OTLPConfig `yaml:"otlp"`
}

// OTLPConfig holds connection settings for the OTLP HTTP exporter.
type OTLPConfig struct {
	Endpoint string            `yaml:"endpoint"` // e.g. "https://otel-collector.internal.example.com:4318"
	Headers  map[string]string `yaml:"headers"`
}

// Setup initialises the global OpenTelemetry TracerProvider and TextMapPropagator
// from cfg. It returns a shutdown function that must be called on process exit to
// flush and close the exporter cleanly.
//
// When cfg.Exporter is "noop" or empty, a no-op provider is installed and the
// shutdown function is a no-op. No external collector is required.
func Setup(ctx context.Context, cfg Config) (shutdown func(context.Context) error, err error) {
	var exp sdktrace.SpanExporter

	switch cfg.Exporter {
	case "otlp":
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpointURL(cfg.OTLP.Endpoint),
		}
		if len(cfg.OTLP.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.OTLP.Headers))
		}
		exp, err = otlptracehttp.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("create otlp exporter: %w", err)
		}

	case "stdout":
		exp, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("create stdout exporter: %w", err)
		}

	case "noop", "":
		// Install a no-op provider so instrumentation code compiles and runs
		// without any collector configured.
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return func(_ context.Context) error { return nil }, nil

	default:
		return nil, fmt.Errorf("unknown telemetry exporter %q; supported: otlp, stdout, noop", cfg.Exporter)
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "portcullis"
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
		resource.WithProcess(),
		resource.WithOS(),
	)
	if err != nil {
		return nil, fmt.Errorf("create otel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tp.Shutdown, nil
}

// TraceIDFromContext extracts the W3C trace ID hex string from the context.
// Returns an empty string if no span is active or the span context is invalid.
func TraceIDFromContext(ctx context.Context) string {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}
