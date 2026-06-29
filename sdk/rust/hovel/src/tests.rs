//! Unit tests for the Rust SDK, run via `rust_test(crate = ":hovel")`.

use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;

use crate::json::{self, Value};
use crate::{
    base64, serve_with, Context, Info, InstalledPayloadDescriptor, LineShellSession, Module,
    ModuleType, Outcome, PayloadProviderRecord, Schema, Session, SessionOptions,
};

#[test]
fn json_round_trips() {
    let text = r#"{"a":1,"b":[true,null,"x\n"],"c":{"d":-2.5}}"#;
    let value = json::parse(text).expect("parse");
    assert_eq!(value.get("a").and_then(Value::as_f64), Some(1.0));
    assert_eq!(value.to_string(), text);
}

#[test]
fn base64_round_trips() {
    for sample in ["", "f", "fo", "foo", "hello, world\n"] {
        let encoded = base64::encode(sample.as_bytes());
        let decoded = base64::decode(&encoded).expect("decode");
        assert_eq!(decoded, sample.as_bytes());
    }
}

#[test]
fn line_shell_answers_commands() {
    let mut shell = LineShellSession::new("mock$ ", true, |command| match command {
        "whoami" => "mock-operator".to_string(),
        other => format!("unknown: {other}"),
    });
    shell.open().unwrap();
    let prompt = shell.read(0).unwrap();
    assert_eq!(prompt, b"mock$ ");
    shell.write(b"whoami\n").unwrap();
    // echo, then output, then a fresh prompt.
    let echo = shell.read(0).unwrap();
    assert_eq!(echo, b"whoami\n");
    let output = shell.read(0).unwrap();
    assert_eq!(output, b"mock-operator\n");
}

#[test]
fn line_shell_handles_backspace() {
    let mut shell = LineShellSession::new("$ ", true, |command| format!("you said: {command}"));
    shell.open().unwrap();
    let _ = shell.read(0).unwrap(); // opening prompt

    // Type "whoamx", press backspace (DEL) to erase the 'x', then "i" + Enter.
    shell.write(b"whoamx").unwrap();
    shell.write(&[0x7f]).unwrap();
    shell.write(b"i\n").unwrap();

    let mut out = Vec::new();
    loop {
        let chunk = shell.read(0).unwrap();
        if chunk.is_empty() {
            break;
        }
        out.extend(chunk);
    }
    let text = String::from_utf8_lossy(&out);
    // The command the handler saw is "whoami", not "whoamxi" or "whoamx\x7fi".
    assert!(
        text.contains("you said: whoami"),
        "command was mangled: {text:?}"
    );
    // The backspace emitted a visual erase sequence.
    assert!(
        out.windows(3).any(|w| w == b"\x08 \x08"),
        "no erase sequence: {out:?}"
    );
}

#[test]
fn line_shell_honors_read_timeout() {
    use std::time::{Duration, Instant};

    let mut shell = LineShellSession::new("$ ", false, |_| String::new());
    shell.open().unwrap();
    assert_eq!(shell.read(0).unwrap(), b"$ "); // opening prompt, non-blocking

    // An idle read with a positive wait blocks for roughly that long, then
    // returns empty — rather than spinning by returning instantly.
    let start = Instant::now();
    let chunk = shell.read(20).unwrap();
    let elapsed = start.elapsed();
    assert!(chunk.is_empty());
    assert!(
        elapsed >= Duration::from_millis(10),
        "idle read returned too fast: {elapsed:?}"
    );

    // wait == 0 stays a non-blocking poll.
    let start = Instant::now();
    assert!(shell.read(0).unwrap().is_empty());
    assert!(start.elapsed() < Duration::from_millis(10));
}

/// A writer that appends to a shared buffer so tests can inspect module output.
#[derive(Clone)]
struct SharedBuf(Rc<RefCell<Vec<u8>>>);

impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct FakeModule {
    with_session: bool,
}

impl Module for FakeModule {
    fn info(&self) -> Info {
        Info {
            name: "fake-rust".into(),
            version: "v0.0.0-test".into(),
            module_type: ModuleType::Survey,
            summary: "fake".into(),
            description: String::new(),
            tags: vec!["example".into(), "test".into()],
            discovery_context: Vec::new(),
        }
    }

    fn schema(&self) -> Schema {
        Schema {
            target_config: vec![crate::Requirement::new(
                "target.host",
                "host",
                "Target host.",
            )],
            ..Schema::default()
        }
    }

    fn run(&self, ctx: &mut Context) -> Outcome {
        ctx.info("running", &[("target", Value::from(ctx.target.as_str()))]);
        if self.with_session {
            let shell = LineShellSession::new("mock$ ", true, |command| {
                if command == "whoami" {
                    "mock-operator".to_string()
                } else {
                    format!("unknown: {command}")
                }
            });
            let sref = ctx
                .open_session(
                    Box::new(shell),
                    SessionOptions::default().with_name("mock shell"),
                )
                .expect("open session");
            return Outcome::ok(vec![("sessionId".into(), Value::from(sref.id.as_str()))])
                .with_summary("opened session");
        }
        let host = ctx.input_str("target.host", &ctx.target);
        Outcome::ok(vec![("host".into(), Value::from(host.as_str()))])
            .with_summary(&format!("surveyed {host}"))
    }
}

struct AgentAwareModule;

impl Module for AgentAwareModule {
    fn info(&self) -> Info {
        Info {
            name: "agent-aware-rust".into(),
            version: "v0.0.0-test".into(),
            module_type: ModuleType::Survey,
            summary: "agent aware".into(),
            description: String::new(),
            tags: Vec::new(),
            discovery_context: Vec::new(),
        }
    }

    fn schema(&self) -> Schema {
        Schema::default()
    }

    fn run(&self, ctx: &mut Context) -> Outcome {
        let entity_kind = ctx
            .agent
            .as_ref()
            .and_then(|agent| agent.get("entity"))
            .and_then(|entity| entity.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut outcome = Outcome::ok(vec![
            ("agentPresent".into(), Value::Bool(ctx.agent.is_some())),
            ("entityKind".into(), Value::from(entity_kind)),
        ]);
        if ctx.agent.is_some() {
            outcome = outcome.with_agent_hint(Value::object(vec![
                ("schema", Value::from("hovel.agent_hint.v1")),
                ("phase", Value::from("execute")),
                ("audience", Value::from("assistant")),
                ("risk", Value::from("low")),
                (
                    "text",
                    Value::from("Prefer read-only inspection before changing state."),
                ),
            ]));
        }
        outcome
    }
}

fn frame(value: Value) -> Vec<u8> {
    let body = value.to_string();
    let mut out = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn request(id: i64, method: &str, params: Value) -> Value {
    Value::object(vec![
        ("jsonrpc", Value::from("2.0")),
        ("id", Value::from(id)),
        ("method", Value::from(method)),
        ("params", params),
    ])
}

#[test]
fn framing_rejects_oversized_frame_before_body_read() {
    let mut cursor = Cursor::new(b"Content-Length: 67108865\r\n\r\n".to_vec());
    let err = crate::framing::read_message(&mut cursor).expect_err("frame should be rejected");
    assert!(err.to_string().contains("exceeds maximum"), "{err}");
}

fn run_session<M: Module>(input: Vec<u8>, module: M) -> Vec<Value> {
    let captured = SharedBuf(Rc::new(RefCell::new(Vec::new())));
    let mut reader = Cursor::new(input);
    serve_with(&module, &mut reader, Box::new(captured.clone())).expect("serve");
    let bytes = captured.0.borrow().clone();
    let mut cursor = Cursor::new(bytes);
    let mut messages = Vec::new();
    while let Some(message) = crate::framing::read_message(&mut cursor).expect("read frame") {
        messages.push(message);
    }
    messages
}

fn responses(messages: &[Value]) -> Vec<&Value> {
    messages.iter().filter(|m| m.get("id").is_some()).collect()
}

#[test]
fn serve_handshake_schema_execute() {
    let mut input = Vec::new();
    input.extend(frame(request(1, "handshake", Value::Object(vec![]))));
    input.extend(frame(request(2, "schema", Value::Object(vec![]))));
    input.extend(frame(request(
        3,
        "execute",
        Value::object(vec![
            ("runId", Value::from("run-1")),
            ("target", Value::from("mock://host")),
            (
                "targetConfig",
                Value::object(vec![("target.host", Value::from("example.test"))]),
            ),
        ]),
    )));
    input.extend(frame(request(4, "shutdown", Value::Object(vec![]))));

    let messages = run_session(
        input,
        FakeModule {
            with_session: false,
        },
    );
    let responses = responses(&messages);
    assert_eq!(responses.len(), 4);

    let handshake = responses[0].get("result").unwrap();
    assert_eq!(
        handshake.get("name").and_then(Value::as_str),
        Some("fake-rust")
    );
    assert_eq!(
        handshake.get("moduleType").and_then(Value::as_str),
        Some("survey")
    );

    let execute = responses[2].get("result").unwrap();
    assert_eq!(
        execute.get("status").and_then(Value::as_str),
        Some("succeeded")
    );
    assert_eq!(
        execute.get("summary").and_then(Value::as_str),
        Some("surveyed example.test")
    );
}

#[test]
fn serve_execute_exposes_optional_agent_context() {
    let mut input = Vec::new();
    input.extend(frame(request(
        1,
        "execute",
        Value::object(vec![
            ("runId", Value::from("run-1")),
            ("target", Value::from("mock://host")),
        ]),
    )));
    input.extend(frame(request(
        2,
        "execute",
        Value::object(vec![
            ("runId", Value::from("run-2")),
            ("target", Value::from("mock://host")),
            (
                "agentContext",
                Value::object(vec![
                    ("schema", Value::from("hovel.agent_context.v1")),
                    (
                        "entity",
                        Value::object(vec![
                            ("id", Value::from("entity-mcp")),
                            ("kind", Value::from("mcp")),
                            ("displayName", Value::from("Codex")),
                            ("agent", Value::Bool(true)),
                        ]),
                    ),
                    ("phase", Value::from("execute")),
                ]),
            ),
        ]),
    )));
    input.extend(frame(request(3, "shutdown", Value::Object(vec![]))));

    let messages = run_session(input, AgentAwareModule);
    let responses = responses(&messages);
    let without_agent = responses[0].get("result").unwrap();
    assert_eq!(
        without_agent
            .get("outputs")
            .and_then(|outputs| outputs.get("agentPresent"))
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(without_agent.get("agentHints").is_none());

    let with_agent = responses[1].get("result").unwrap();
    assert_eq!(
        with_agent
            .get("outputs")
            .and_then(|outputs| outputs.get("entityKind"))
            .and_then(Value::as_str),
        Some("mcp")
    );
    let hints = match with_agent.get("agentHints") {
        Some(Value::Array(items)) => items,
        other => panic!("missing agent hints: {other:?}"),
    };
    assert_eq!(
        hints[0].get("schema").and_then(Value::as_str),
        Some("hovel.agent_hint.v1")
    );
}

#[test]
fn outcome_serializes_installed_payload_descriptors() {
    let payload = InstalledPayloadDescriptor::new(
        "squatter",
        "squatter/windows/x86/xp-sp3/tcp-bind/pe-exe",
        "10.0.0.42",
    )
    .with_payload_version("0.1.0")
    .with_transport("tcp-bind")
    .with_endpoint("10.0.0.42:9101")
    .with_instance_key("squatter:10.0.0.42:9101")
    .with_stamp_id("stamp-1")
    .with_artifact_id("artifact-1")
    .with_supports_reconnect(true)
    .with_cleanup(PayloadProviderRecord::new(
        "squatter.cleanup.tcp_bind",
        vec![(
            "remotePath".into(),
            Value::from(r"C:\Windows\Temp\n4x9q2.exe"),
        )],
    ))
    .with_reconnect(
        PayloadProviderRecord::new(
            "squatter.reconnect.tcp_bind",
            vec![
                ("host".into(), Value::from("10.0.0.42")),
                ("port".into(), Value::from(9101_i64)),
            ],
        )
        .with_schema_version("1"),
    )
    .with_metadata("launch_method", Value::from("rust-test"));

    let result = Outcome::ok(vec![("target".into(), Value::from("10.0.0.42"))])
        .with_installed_payload(payload)
        .to_value(Vec::new());

    let installed = match result.get("installedPayloads") {
        Some(Value::Array(items)) => &items[0],
        other => panic!("missing installed payloads: {other:?}"),
    };
    assert_eq!(
        installed.get("provider").and_then(Value::as_str),
        Some("squatter")
    );
    assert_eq!(
        installed.get("payloadId").and_then(Value::as_str),
        Some("squatter/windows/x86/xp-sp3/tcp-bind/pe-exe")
    );
    assert_eq!(
        installed.get("supportsReconnect").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        installed
            .get("reconnect")
            .and_then(|v| v.get("descriptor"))
            .and_then(|v| v.get("port"))
            .and_then(Value::as_f64),
        Some(9101.0)
    );
    assert_eq!(
        installed
            .get("cleanup")
            .and_then(|v| v.get("descriptor"))
            .and_then(|v| v.get("remotePath"))
            .and_then(Value::as_str),
        Some(r"C:\Windows\Temp\n4x9q2.exe")
    );
}

#[test]
fn serve_session_round_trip() {
    let mut input = Vec::new();
    input.extend(frame(request(
        1,
        "execute",
        Value::object(vec![
            ("runId", Value::from("run-1")),
            ("target", Value::from("mock://host")),
        ]),
    )));
    // The opening prompt plus the whoami exchange are driven by session RPCs.
    let session_id = "run-1-session-1";
    input.extend(frame(request(
        2,
        "session/read",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            ("timeoutMs", Value::from(0_i64)),
        ]),
    )));
    input.extend(frame(request(
        3,
        "session/write",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            ("data", Value::from(base64::encode(b"whoami\n").as_str())),
        ]),
    )));
    input.extend(frame(request(
        4,
        "session/read",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            ("timeoutMs", Value::from(0_i64)),
        ]),
    )));
    input.extend(frame(request(
        5,
        "session/read",
        Value::object(vec![
            ("sessionId", Value::from(session_id)),
            ("timeoutMs", Value::from(0_i64)),
        ]),
    )));
    input.extend(frame(request(6, "shutdown", Value::Object(vec![]))));

    let messages = run_session(input, FakeModule { with_session: true });
    let responses = responses(&messages);

    let execute = responses[0].get("result").unwrap();
    let sessions = match execute.get("sessions") {
        Some(Value::Array(items)) => items,
        _ => panic!("missing sessions"),
    };
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].get("id").and_then(Value::as_str),
        Some(session_id)
    );

    // Concatenate all decoded session/read payloads and confirm the shell spoke.
    let mut output = Vec::new();
    for response in &responses[1..] {
        if let Some(result) = response.get("result") {
            if let Some(data) = result.get("data").and_then(Value::as_str) {
                output.extend(base64::decode(data).unwrap());
            }
        }
    }
    let text = String::from_utf8_lossy(&output);
    assert!(text.contains("mock$"), "missing prompt in {text:?}");
    assert!(
        text.contains("mock-operator"),
        "missing whoami output in {text:?}"
    );
}
