package telemetry

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

var (
	Tracer                trace.Tracer
	Meter                 metric.Meter
	ToolCallsCounter      metric.Int64Counter
	ToolDurationHistogram metric.Float64Histogram
)

// InitTelemetry bootstraps OpenTelemetry tracing and Prometheus metrics exporting
func InitTelemetry(serviceName string) (*sdktrace.TracerProvider, error) {
	ctx := context.Background()

	// 1. Configure Resources (metadata about our service)
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create telemetry resource: %w", err)
	}

	// 2. Set up Tracing (using simple stdout exporter for stub, exportable to Jaeger/OTLP)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	Tracer = otel.Tracer("mcp-api-gateway")

	// 3. Set up Metrics with Prometheus Exporter
	exporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize prometheus exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)
	Meter = otel.Meter("mcp-api-gateway")

	// 4. Register standard Enterprise metrics
	ToolCallsCounter, err = Meter.Int64Counter("mcp_gateway_tool_calls_total",
		metric.WithDescription("Total number of MCP tool calls processed"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create tool calls counter: %w", err)
	}

	ToolDurationHistogram, err = Meter.Float64Histogram("mcp_gateway_tool_duration_seconds",
		metric.WithDescription("Duration of target API call execution"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create tool duration histogram: %w", err)
	}

	return tp, nil
}

// ServeMetrics exposes the Prometheus scrape route
func ServeMetrics() http.Handler {
	return promhttp.Handler()
}
