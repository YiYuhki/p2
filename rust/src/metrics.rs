//! Prometheus collectors for the gateway, on a private registry. Port of the Go
//! `internal/metrics` (same metric names and labels).

use std::time::Instant;

use chrono::{DateTime, Utc};
use prometheus::{
    register_gauge_vec_with_registry, register_histogram_vec_with_registry,
    register_histogram_with_registry, register_int_counter_vec_with_registry, Encoder, GaugeVec,
    Histogram, HistogramVec, IntCounterVec, Registry, TextEncoder,
};

/// All gateway metrics, registered on a private registry.
pub struct Metrics {
    registry: Registry,
    pub inbound_messages: IntCounterVec,
    pub attachments: IntCounterVec,
    pub verdicts: IntCounterVec,
    pub outbound_messages: IntCounterVec,
    pub dlp_findings: IntCounterVec,
    pub dlp_scan_seconds: Histogram,
    pub external_tool_seconds: HistogramVec,
    pub holds: IntCounterVec,
    pub portal_requests: IntCounterVec,
    pub inbound_auth: IntCounterVec,
    pub tls_cert_expiry: GaugeVec,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let r = Registry::new();
        let inbound_messages = register_int_counter_vec_with_registry!(
            "secmail_inbound_messages_total",
            "Inbound messages processed, by result (relayed/rejected/tempfail).",
            &["result"],
            r
        )
        .unwrap();
        let attachments = register_int_counter_vec_with_registry!(
            "secmail_attachments_total",
            "Attachments quarantined, by initial status.",
            &["status"],
            r
        )
        .unwrap();
        let verdicts = register_int_counter_vec_with_registry!(
            "secmail_verdicts_total",
            "Analyzer verdicts applied, by status.",
            &["status"],
            r
        )
        .unwrap();
        let outbound_messages = register_int_counter_vec_with_registry!(
            "secmail_outbound_messages_total",
            "Outbound messages inspected, by DLP action.",
            &["action"],
            r
        )
        .unwrap();
        let dlp_findings = register_int_counter_vec_with_registry!(
            "secmail_dlp_findings_total",
            "DLP findings, by severity.",
            &["severity"],
            r
        )
        .unwrap();
        let dlp_scan_seconds = register_histogram_with_registry!(
            "secmail_dlp_scan_seconds",
            "Outbound DLP scan duration per message.",
            vec![0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0],
            r
        )
        .unwrap();
        let external_tool_seconds = register_histogram_vec_with_registry!(
            "secmail_external_tool_seconds",
            "External tool runtime, by tool.",
            &["tool"],
            vec![0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 60.0],
            r
        )
        .unwrap();
        let holds = register_int_counter_vec_with_registry!(
            "secmail_holds_total",
            "DLP holds, by event (created/released/rejected/expired).",
            &["event"],
            r
        )
        .unwrap();
        let portal_requests = register_int_counter_vec_with_registry!(
            "secmail_portal_requests_total",
            "Download-portal token lookups, by outcome.",
            &["outcome"],
            r
        )
        .unwrap();
        let inbound_auth = register_int_counter_vec_with_registry!(
            "secmail_inbound_auth_total",
            "Inbound authentication results, by method and result.",
            &["method", "result"],
            r
        )
        .unwrap();
        let tls_cert_expiry = register_gauge_vec_with_registry!(
            "secmail_tls_cert_expiry_timestamp_seconds",
            "Serving-certificate NotAfter as a Unix timestamp, by component.",
            &["component"],
            r
        )
        .unwrap();

        Metrics {
            registry: r,
            inbound_messages,
            attachments,
            verdicts,
            outbound_messages,
            dlp_findings,
            dlp_scan_seconds,
            external_tool_seconds,
            holds,
            portal_requests,
            inbound_auth,
            tls_cert_expiry,
        }
    }

    /// Records a component's serving-certificate expiry.
    pub fn set_cert_expiry(&self, component: &str, not_after: DateTime<Utc>) {
        self.tls_cert_expiry
            .with_label_values(&[component])
            .set(not_after.timestamp() as f64);
    }

    /// Times an external-tool call: hold the returned guard; dropping it records
    /// the elapsed seconds under `tool`.
    pub fn time_tool(&self, tool: &str) -> ToolTimer<'_> {
        ToolTimer {
            metrics: self,
            tool: tool.to_string(),
            start: Instant::now(),
        }
    }

    /// Renders the metrics in Prometheus text format.
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        encoder.encode(&families, &mut buf).unwrap();
        String::from_utf8(buf).unwrap_or_default()
    }
}

/// Dropping this records the elapsed external-tool time.
pub struct ToolTimer<'a> {
    metrics: &'a Metrics,
    tool: String,
    start: Instant,
}

impl Drop for ToolTimer<'_> {
    fn drop(&mut self) {
        self.metrics
            .external_tool_seconds
            .with_label_values(&[&self.tool])
            .observe(self.start.elapsed().as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_render() {
        let m = Metrics::new();
        m.inbound_messages.with_label_values(&["relayed"]).inc();
        m.inbound_messages.with_label_values(&["relayed"]).inc();
        m.inbound_auth.with_label_values(&["spf", "pass"]).inc();
        m.holds.with_label_values(&["created"]).inc();
        let out = m.render();
        assert!(out.contains("secmail_inbound_messages_total"));
        assert!(out.contains(r#"result="relayed""#));
        assert!(out.contains(r#"secmail_inbound_messages_total{result="relayed"} 2"#));
        assert!(out.contains("secmail_inbound_auth_total"));
    }

    #[test]
    fn cert_expiry_gauge() {
        let m = Metrics::new();
        let t = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        m.set_cert_expiry("smtp", t);
        let out = m.render();
        assert!(out.contains("secmail_tls_cert_expiry_timestamp_seconds"));
        assert!(out.contains("1700000000"));
    }

    #[test]
    fn tool_timer_records() {
        let m = Metrics::new();
        {
            let _t = m.time_tool("ocr");
        }
        assert!(m
            .render()
            .contains(r#"secmail_external_tool_seconds_count{tool="ocr"}"#));
    }
}
