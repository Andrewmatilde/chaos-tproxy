//! Types generated from `schemas/chaos-tproxy.openapi.yaml`.
//!
//! Don't edit `openapi.rs` by hand — see the `tools/codegen` crate.
//!
//! These are the **OpenAPI-contract** types: the canonical wire
//! shape exchanged with any controller (Rust today, Go in the
//! future). The legacy hand-written types in `crate::raw_config`
//! remain in place for now because the action engine + the rule
//! conversion logic are still written against them; future PRs will
//! migrate them to consume the generated types directly.

pub mod openapi;
