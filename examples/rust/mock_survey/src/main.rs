//! mock-survey-rust is an example Hovel survey module written in Rust.
//!
//! It mirrors the Python example in examples/python/mock_survey: it collects a
//! couple of "facts" about a target without touching anything real. Register it
//! in a modules config with a "command" entry pointing at the built binary.

use std::thread::sleep;
use std::time::Duration;

use hovel::json::Value;
use hovel::{Context, Info, Module, ModuleType, Outcome, Requirement, Schema};

struct MockSurvey;

impl Module for MockSurvey {
    fn info(&self) -> Info {
        Info {
            name: "mock-survey-rust".into(),
            version: "v0.0.0-example".into(),
            module_type: ModuleType::Survey,
            summary: "Collect example target facts.".into(),
            description: "Example Rust survey module for the Hovel stdio JSON-RPC runtime.".into(),
            tags: vec!["example".into(), "survey".into(), "rust".into()],
            discovery_context: Vec::new(),
        }
    }

    fn schema(&self) -> Schema {
        Schema {
            target_config: vec![
                Requirement::new("target.host", "host", "Target host name or IP address."),
                Requirement::new("target.port", "port", "Target TCP port."),
            ],
            ..Schema::default()
        }
    }

    fn run(&self, ctx: &mut Context) -> Outcome {
        let host = ctx.input_str("target.host", &ctx.target);
        let port = ctx.input_str("target.port", "unknown");
        let fields = [
            ("host", Value::from(host.as_str())),
            ("port", Value::from(port.as_str())),
        ];

        ctx.info("connecting to target", &fields);
        sleep(Duration::from_millis(500));
        ctx.info("connected to target, surveying ...", &fields);
        sleep(Duration::from_millis(1500));
        ctx.info("example survey completed", &fields);

        let facts = Value::object(vec![
            ("host", Value::from(host.as_str())),
            ("port", Value::from(port.as_str())),
            ("reachable", Value::from(true)),
        ]);
        Outcome::ok(vec![("facts".into(), facts)])
            .with_summary(&format!("example survey reached {host}:{port}"))
    }
}

fn main() {
    hovel::serve(MockSurvey);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_is_a_rust_survey() {
        let info = MockSurvey.info();
        assert_eq!(info.name, "mock-survey-rust");
        assert_eq!(info.module_type, ModuleType::Survey);
    }

    #[test]
    fn schema_requires_host_and_port() {
        let schema = MockSurvey.schema();
        assert_eq!(schema.target_config.len(), 2);
        assert_eq!(schema.target_config[0].key, "target.host");
    }
}
