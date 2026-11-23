//! secmail — a secure mail gateway (Rust port of the Go implementation).
//!
//! This crate is a work-in-progress port of the Go `secmail` gateway. Modules
//! are ported subsystem by subsystem; the pure-logic layers land first and the
//! async I/O layers (SMTP proxy, HTTP portal, Postgres/Redis stores) follow.

pub mod arc;
pub mod dnsbl;
pub mod greylist;
pub mod ratelimit;
