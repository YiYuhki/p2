// Package metrics holds the Prometheus collectors for the gateway. All
// metrics are registered on a private registry exposed via Handler so tests
// and multiple instances do not clash with the global default registry.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	reg = prometheus.NewRegistry()

	// InboundMessages counts messages relayed by the inbound proxy.
	InboundMessages = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "secmail_inbound_messages_total",
		Help: "Inbound messages processed, by result (relayed/rejected/tempfail).",
	}, []string{"result"})

	// Attachments counts quarantined attachments by their initial status.
	Attachments = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "secmail_attachments_total",
		Help: "Attachments quarantined, by initial status (pending/reused-clean/reused-malicious).",
	}, []string{"status"})

	// Verdicts counts analyzer verdicts applied.
	Verdicts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "secmail_verdicts_total",
		Help: "Analyzer verdicts applied, by status.",
	}, []string{"status"})

	// OutboundMessages counts outbound messages by DLP action.
	OutboundMessages = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "secmail_outbound_messages_total",
		Help: "Outbound messages inspected, by DLP action (allow/notify/hold/block/exempt).",
	}, []string{"action"})

	// DLPFindings counts DLP findings by severity.
	DLPFindings = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "secmail_dlp_findings_total",
		Help: "DLP findings, by severity (high/medium/low).",
	}, []string{"severity"})

	// DLPScanSeconds measures how long a full message scan takes.
	DLPScanSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "secmail_dlp_scan_seconds",
		Help:    "Outbound DLP scan duration per message.",
		Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 30, 60},
	})

	// ExternalToolSeconds measures external tool (OCR/convert/archive) runtime.
	ExternalToolSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "secmail_external_tool_seconds",
		Help:    "External tool runtime, by tool (ocr/pdf/heif/archive).",
		Buckets: []float64{0.05, 0.1, 0.5, 1, 2, 5, 10, 20, 60},
	}, []string{"tool"})

	// Holds counts DLP holds created and their outcomes.
	Holds = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "secmail_holds_total",
		Help: "DLP holds, by event (created/released/rejected/expired).",
	}, []string{"event"})

	// PortalRequests counts download-portal token lookups by outcome. A spike
	// in notfound/throttled is the signature of token enumeration.
	PortalRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "secmail_portal_requests_total",
		Help: "Download-portal token lookups, by outcome (ok/notfound/throttled/denied/error).",
	}, []string{"outcome"})

	// InboundAuth counts inbound message authentication results by method and
	// outcome (e.g. spf=fail, dkim=pass). A rise in fail/none can indicate
	// spoofing or a misconfigured sender.
	InboundAuth = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "secmail_inbound_auth_total",
		Help: "Inbound authentication results, by method (spf/dkim) and result (pass/fail/none/...).",
	}, []string{"method", "result"})
)

func init() {
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		InboundMessages, Attachments, Verdicts, OutboundMessages,
		DLPFindings, DLPScanSeconds, ExternalToolSeconds, Holds, PortalRequests, InboundAuth,
	)
}

// Handler serves the metrics in Prometheus text format.
func Handler() http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

// Time returns a function that records the elapsed seconds into the given
// external-tool label when called (use with defer).
func Time(tool string) func() {
	start := time.Now()
	return func() { ExternalToolSeconds.WithLabelValues(tool).Observe(time.Since(start).Seconds()) }
}
