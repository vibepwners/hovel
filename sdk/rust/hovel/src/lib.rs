//! The Rust SDK for writing Hovel modules.
//!
//! A module is a separate process that the Hovel daemon launches and drives over
//! a small JSON-RPC 2.0 protocol carried on stdin/stdout, with each message
//! framed by a `Content-Length` header. Implement [`Module`] and hand it to
//! [`serve`]; this crate takes care of framing, dispatch, logging, and sessions.
//!
//! To stay dependency-free this crate hand-rolls a tiny [`json`] layer and
//! [`base64`] codec instead of pulling in `serde_json`. Real modules are free to
//! use whatever crates they like.
//!
//! ```no_run
//! use hovel::{Context, Info, Module, ModuleType, Outcome, Schema, json::Value};
//!
//! struct Hello;
//!
//! impl Module for Hello {
//!     fn info(&self) -> Info {
//!         Info {
//!             name: "hello-rust".into(),
//!             version: "v0.0.0".into(),
//!             module_type: ModuleType::Survey,
//!             summary: "say hello".into(),
//!             description: String::new(),
//!             tags: vec!["example".into()],
//!         }
//!     }
//!     fn schema(&self) -> Schema { Schema::default() }
//!     fn run(&self, ctx: &mut Context) -> Outcome {
//!         ctx.info("hello", &[("target", Value::from(ctx.target.as_str()))]);
//!         Outcome::ok(vec![("greeting".into(), Value::from("hi"))])
//!     }
//! }
//!
//! fn main() { hovel::serve(Hello); }
//! ```

pub mod base64;
pub mod json;

mod context;
mod framing;
mod module;
mod result;
mod server;
mod session;

#[cfg(test)]
mod tests;

pub use context::Context;
pub use module::{Info, Module, ModuleType, Requirement, Schema};
pub use result::{Artifact, Finding, InstalledPayloadDescriptor, Outcome, PayloadProviderRecord};
pub use server::{serve, serve_with};
pub use session::{LineShellSession, Session, SessionOptions, SessionRef};
