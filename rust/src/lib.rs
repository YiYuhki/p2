//! secmail — a secure mail gateway (Rust port of the Go implementation).
//!
//! This crate is a work-in-progress port of the Go `secmail` gateway. Modules
//! are ported subsystem by subsystem; the pure-logic layers land first and the
//! async I/O layers (SMTP proxy, HTTP portal, Postgres/Redis stores) follow.

pub mod arc;
pub mod config;
pub mod dlp;
pub mod dnsbl;
pub mod gateway;
pub mod greylist;
pub mod http;
pub mod internalapi;
pub mod metrics;
pub mod mimeproc;
pub mod model;
pub mod outbound;
pub mod processor;
pub mod queue;
pub mod ratelimit;
pub mod smtpclient;
pub mod storage;
pub mod store;
pub mod webhook;
