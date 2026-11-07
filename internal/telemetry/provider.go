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
// portcullis-gate, portcullis-keep, and portcullis-guard.
package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	prometheusexp "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// httpDurationBuckets are the default histogram bucket boundaries (in seconds)
// used for all HTTP latency histograms. These match Prometheus defaults scaled
// to seconds (not milliseconds).
var httpDurationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// MetricsConfig configures the Prometheus scrape endpoint.
type MetricsConfig struct {
	// Enabled controls whether the /metrics endpoint is served.
	// A nil pointer means "use the component default".
	// Keep, Guard, and Multi-Tenant Gate default to true; Single-Tenant Gate forces false.
	Enabled *bool `yaml:"enabled"`
	// Path is the HTTP path for the Prometheus scrape endpoint.
	// Defaults to "/metrics" when empty.
	Path string `yaml:"path"`
}

// IsEnabled returns whether metrics are enabled, applying defaultOn when Enabled is nil.
func (m MetricsConfig) IsEnabled(defaultOn bool) bool {
	if m.Enabled == nil {
		return defaultOn
	}
	return *m.Enabled
}

// EffectivePath returns the scrape path, defaulting to "/metrics".
func (m MetricsConfig) EffectivePath() string {
	p := m.Path
	if p == "" {
		return "/metrics"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// Config configures OpenTelemetry tracing and metrics for a Portcullis component.
type Config struct {
	// Exporter selects the trace exporter: "otlp", "stdout", or "noop" (default).
	Exporter    string        `yaml:"exporter"`
	ServiceName string        `yaml:"service_name"`
	OTLP        OTLPConfig    `yaml:"otlp"`
	Metrics     MetricsConfig `yaml:"metrics"`
}

// OTLPConfig holds connection settings for the OTLP HTTP exporter.
type OTLPConfig struct {
	Endpoint string            `yaml:"endpoint"` // e.g. "https://otel-collector.internal.example.com:4318"
	Headers  map[string]string `yaml:"headers"`
}

// package-level storage for the current metrics handler, protected by a mutex
// to allow safe concurrent access and clean test isolation.
var (
	metricsHandlerMu sync.RWMutex
	metricsHandler   http.Handler = http.NotFoundHandler()
)

func setMetricsHandler(h http.Handler) {
	metricsHandlerMu.Lock()
	defer metricsHandlerMu.Unlock()
	metricsHandler = h
}

// MetricsHandler returns the HTTP handler for the Prometheus scrape endpoint.
// Returns http.NotFoundHandler() when metrics are disabled.
// The handler is safe to call concurrently.
func MetricsHandler() http.Handler {
	metricsHandlerMu.RLock()
	defer metricsHandlerMu.RUnlock()
	return metricsHandler
}

// Meter returns a named OpenTelemetry Meter from the global MeterProvider.
// When metrics are disabled, returns a no-op meter that is safe to use without panicking.
func Meter(name string) metric.Meter {
	return otel.GetMeterProvider().Meter(name)
}

// Setup initialises the global OpenTelemetry TracerProvider, MeterProvider, and
// TextMapPropagator from cfg. It returns a shutdown function that must be called
// on process exit to flush and close both providers cleanly.
//
// Tracing and metrics are independently configured: an omitted or "noop" trace
// exporter does not disable metrics. Metrics are controlled solely by cfg.Metrics.
//
// The metricsDefaultOn parameter is provided by the calling component:
//   - true for Keep, Guard, and Multi-Tenant Gate
//   - false for Single-Tenant Gate (forces metrics off regardless of cfg.Metrics.Enabled)
//
// When both are noop/disabled, a lightweight shutdown function is returned.
func Setup(ctx context.Context, cfg Config, metricsDefaultOn bool) (shutdown func(context.Context) error, err error) {
	metricsOn := cfg.Metrics.IsEnabled(metricsDefaultOn)

	// --- Trace provider ---
	traceShutdown, res, traceErr := setupTrace(ctx, cfg)
	if traceErr != nil {
		return nil, traceErr
	}

	// --- Metrics provider ---
	metricShutdown := setupMetrics(ctx, cfg, metricsOn, res)

	// Combined shutdown: attempt both, collect errors.
	return func(ctx context.Context) error {
		var errs []error
		if err := traceShutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("trace shutdown: %w", err))
		}
		if err := metricShutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("metric shutdown: %w", err))
		}
		if len(errs) == 1 {
			return errs[0]
		}
		if len(errs) > 1 {
			return fmt.Errorf("telemetry shutdown errors: %v", errs)
		}
		return nil
	}, nil
}

// setupTrace initialises the global TracerProvider and TextMapPropagator.
// Returns (shutdown, resource, error). resource may be nil for the noop path.
func setupTrace(ctx context.Context, cfg Config) (shutdown func(context.Context) error, res *resource.Resource, err error) {
	noop := func(_ context.Context) error { return nil }

	switch cfg.Exporter {
	case "otlp":
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpointURL(cfg.OTLP.Endpoint),
		}
		if len(cfg.OTLP.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.OTLP.Headers))
		}
		exp, expErr := otlptracehttp.New(ctx, opts...)
		if expErr != nil {
			return nil, nil, fmt.Errorf("create otlp exporter: %w", expErr)
		}
		r, resErr := buildResource(ctx, cfg.ServiceName)
		if resErr != nil {
			slog.Warn("telemetry: failed to build resource; using default", "error", resErr)
			r = resource.Default()
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(r),
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
		)
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return tp.Shutdown, r, nil

	case "stdout":
		exp, expErr := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if expErr != nil {
			return nil, nil, fmt.Errorf("create stdout exporter: %w", expErr)
		}
		r, resErr := buildResource(ctx, cfg.ServiceName)
		if resErr != nil {
			slog.Warn("telemetry: failed to build resource; using default", "error", resErr)
			r = resource.Default()
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(r),
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
		)
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return tp.Shutdown, r, nil

	case "noop", "":
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return noop, nil, nil

	default:
		return nil, nil, fmt.Errorf("unknown telemetry exporter %q; supported: otlp, stdout, noop", cfg.Exporter)
	}
}

// setupMetrics initialises the global MeterProvider and sets the package-level
// MetricsHandler. When disabled, it installs a noop provider and 404 handler.
// Always returns a non-nil shutdown function.
func setupMetrics(ctx context.Context, cfg Config, enabled bool, traceRes *resource.Resource) func(context.Context) error {
	noop := func(_ context.Context) error { return nil }

	if !enabled {
		otel.SetMeterProvider(metricnoop.NewMeterProvider())
		setMetricsHandler(http.NotFoundHandler())
		return noop
	}

	// Use the resource built for the trace provider, or build one if trace is noop.
	res := traceRes
	if res == nil {
		var resErr error
		res, resErr = buildResource(ctx, cfg.ServiceName)
		if resErr != nil {
			slog.Warn("telemetry: failed to build resource for metrics; using default", "error", resErr)
			res = resource.Default()
		}
	}

	reg := promclient.NewRegistry()
	exporter, expErr := prometheusexp.New(prometheusexp.WithRegisterer(reg))
	if expErr != nil {
		slog.Warn("telemetry: failed to create prometheus exporter; metrics disabled", "error", expErr)
		otel.SetMeterProvider(metricnoop.NewMeterProvider())
		setMetricsHandler(http.NotFoundHandler())
		return noop
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
		sdkmetric.WithResource(res),
		sdkmetric.WithView(sdkmetric.NewView(
			sdkmetric.Instrument{Kind: sdkmetric.InstrumentKindHistogram},
			sdkmetric.Stream{
				Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
					Boundaries: httpDurationBuckets,
				},
			},
		)),
	)

	otel.SetMeterProvider(mp)
	setMetricsHandler(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return mp.Shutdown
}

// buildResource creates a standard OTel resource with service, process, and OS attributes.
func buildResource(ctx context.Context, serviceName string) (*resource.Resource, error) {
	if serviceName == "" {
		serviceName = "portcullis"
	}
	return resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
		resource.WithProcess(),
		resource.WithOS(),
	)
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
