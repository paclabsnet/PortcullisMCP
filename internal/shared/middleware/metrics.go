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

package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// attrEndpoint, attrMethod, attrStatusCode, attrListener produce bounded label
// key-value pairs for HTTP metrics. Using helpers ensures consistent key names
// across all call sites.
func attrEndpoint(v string) attribute.KeyValue  { return attribute.String("endpoint", v) }
func attrMethod(v string) attribute.KeyValue    { return attribute.String("method", v) }
func attrStatusCode(v string) attribute.KeyValue { return attribute.String("status_code", v) }
func attrListener(v string) attribute.KeyValue  { return attribute.String("listener", v) }

// HTTPMetrics holds the HTTP request count and duration instruments for a component.
// Create one per component using NewHTTPMetrics and wire it via Middleware().
type HTTPMetrics struct {
	requestsTotal   metric.Int64Counter
	requestDuration metric.Float64Histogram
}

// NewHTTPMetrics creates the counter and histogram instruments for a component.
// component is the Portcullis component name used as a prefix, e.g. "keep", "guard", "gate".
// An optional listenerLabel parameter includes a "listener" dimension on the instruments
// (used by Guard which has two listeners).
func NewHTTPMetrics(meter metric.Meter, component string) (*HTTPMetrics, error) {
	prefix := "portcullis_" + component
	counter, err := meter.Int64Counter(
		prefix+"_http_requests_total",
		metric.WithDescription("Total inbound HTTP requests."),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, fmt.Errorf("create %s request counter: %w", component, err)
	}
	hist, err := meter.Float64Histogram(
		prefix+"_http_request_duration_seconds",
		metric.WithDescription("Latency distribution of inbound HTTP requests."),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("create %s request duration histogram: %w", component, err)
	}
	return &HTTPMetrics{requestsTotal: counter, requestDuration: hist}, nil
}

// Middleware returns an HTTP middleware that records request count and latency.
// routeNormalizer maps a request path to a bounded route label string; it must
// never return raw paths or dynamic segments.
func (m *HTTPMetrics) Middleware(routeNormalizer func(path string) string) func(http.Handler) http.Handler {
	return m.middlewareWithListener(routeNormalizer, "")
}

// MiddlewareWithListener is like Middleware but also tags requests with a
// listener label (used by Guard's dual-listener setup).
func (m *HTTPMetrics) MiddlewareWithListener(routeNormalizer func(path string) string, listener string) func(http.Handler) http.Handler {
	return m.middlewareWithListener(routeNormalizer, listener)
}

func (m *HTTPMetrics) middlewareWithListener(routeNormalizer func(path string) string, listener string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rw, r)

			elapsed := time.Since(start).Seconds()
			route := routeNormalizer(r.URL.Path)
			method := normalizeMethod(r.Method)
			status := strconv.Itoa(rw.status)

			ctx := r.Context()
			if listener != "" {
				m.requestsTotal.Add(ctx, 1,
					metric.WithAttributes(
						attrListener(listener),
						attrEndpoint(route),
						attrMethod(method),
						attrStatusCode(status),
					),
				)
				m.requestDuration.Record(ctx, elapsed,
					metric.WithAttributes(
						attrListener(listener),
						attrEndpoint(route),
						attrMethod(method),
					),
				)
			} else {
				m.requestsTotal.Add(ctx, 1,
					metric.WithAttributes(
						attrEndpoint(route),
						attrMethod(method),
						attrStatusCode(status),
					),
				)
				m.requestDuration.Record(ctx, elapsed,
					metric.WithAttributes(
						attrEndpoint(route),
						attrMethod(method),
					),
				)
			}
		})
	}
}

// statusRecorder wraps http.ResponseWriter to capture the written status code.
// It implements http.Flusher and http.Unwrap to preserve streaming/unwrapping.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if !r.wroteHeader {
		r.status = status
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
		// status stays at 200 (default)
	}
	return r.ResponseWriter.Write(b)
}

// Flush implements http.Flusher to preserve streaming behavior.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter, enabling http.ResponseController
// and similar wrapping-aware utilities to access the original writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// normalizeMethod returns the method string for a bounded set of HTTP methods.
// Unknown methods collapse to "OTHER" to prevent cardinality growth.
func normalizeMethod(method string) string {
	switch strings.ToUpper(method) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return strings.ToUpper(method)
	default:
		return "OTHER"
	}
}

// KeepRouteNormalizer returns the route label for a Keep endpoint path.
// Paths not matching a known route return "other".
func KeepRouteNormalizer(path string) string {
	switch path {
	case "/call":
		return "/call"
	case "/authorize":
		return "/authorize"
	case "/tools":
		return "/tools"
	case "/healthz":
		return "/healthz"
	case "/readyz":
		return "/readyz"
	case "/metrics":
		return "/metrics"
	case "/admin/reload":
		return "/admin/reload"
	case "/oauth/callback":
		return "/oauth/callback"
	default:
		if strings.HasPrefix(path, "/config/") {
			return "/config/{resource}"
		}
		return "other"
	}
}

// GuardRouteNormalizer returns the route label for a Guard endpoint path.
func GuardRouteNormalizer(path string) string {
	switch path {
	case "/approve":
		return "/approve"
	case "/token/deposit":
		return "/token/deposit"
	case "/token/claim":
		return "/token/claim"
	case "/pending":
		return "/pending"
	case "/healthz":
		return "/healthz"
	case "/readyz":
		return "/readyz"
	case "/metrics":
		return "/metrics"
	case "/auth/login":
		return "/auth/login"
	case "/auth/callback":
		return "/auth/callback"
	case "/auth/logout":
		return "/auth/logout"
	default:
		return "other"
	}
}

// GateRouteNormalizer returns the route label for a Gate endpoint path.
func GateRouteNormalizer(path string) string {
	switch path {
	case "/mcp", "/mcp/":
		return "/mcp"
	case "/healthz":
		return "/healthz"
	case "/readyz":
		return "/readyz"
	case "/metrics":
		return "/metrics"
	default:
		if strings.HasPrefix(path, "/mcp") {
			return "/mcp"
		}
		return "other"
	}
}
