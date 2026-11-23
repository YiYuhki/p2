//! secmail binary entry point.
//!
//! The command surface (run, validate-config, dkim-keygen, …) is ported after
//! the subsystem libraries land. For now it reports build/port status so the
//! crate produces a runnable binary.

fn main() {
    println!(
        "secmail (Rust port) — ported modules: arc::canon, dnsbl, greylist, ratelimit. \
         Subsystem porting in progress."
    );
}
