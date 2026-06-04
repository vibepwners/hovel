//! Unit tests for the Rust SDK, run via `rust_test(crate = ":hovel")`.

use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;

use crate::json::{self, Value};
use crate::{base64, serve_with, Context, Info, LineShellSession, Module, ModuleType, Outcome, Schema, Session, SessionOptions};

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
        }
    }

    fn schema(&self) -> Schema {
        Schema {
            target_config: vec![crate::Requirement::new("target.host", "host", "Target host.")],
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
                .open_session(Box::new(shell), SessionOptions::default().with_name("mock shell"))
                .expect("open session");
            return Outcome::ok(vec![("sessionId".into(), Value::from(sref.id.as_str()))])
                .with_summary("opened session");
        }
        let host = ctx.input_str("target.host", &ctx.target);
        Outcome::ok(vec![("host".into(), Value::from(host.as_str()))])
            .with_summary(&format!("surveyed {host}"))
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

fn run_session(input: Vec<u8>, module: FakeModule) -> Vec<Value> {
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
            ("targetConfig", Value::object(vec![("target.host", Value::from("example.test"))])),
        ]),
    )));
    input.extend(frame(request(4, "shutdown", Value::Object(vec![]))));

    let messages = run_session(input, FakeModule { with_session: false });
    let responses = responses(&messages);
    assert_eq!(responses.len(), 4);

    let handshake = responses[0].get("result").unwrap();
    assert_eq!(handshake.get("name").and_then(Value::as_str), Some("fake-rust"));
    assert_eq!(handshake.get("moduleType").and_then(Value::as_str), Some("survey"));

    let execute = responses[2].get("result").unwrap();
    assert_eq!(execute.get("status").and_then(Value::as_str), Some("succeeded"));
    assert_eq!(execute.get("summary").and_then(Value::as_str), Some("surveyed example.test"));
}

#[test]
fn serve_session_round_trip() {
    let mut input = Vec::new();
    input.extend(frame(request(1, "execute", Value::object(vec![("runId", Value::from("run-1")), ("target", Value::from("mock://host"))]))));
    // The opening prompt plus the whoami exchange are driven by session RPCs.
    let session_id = "run-1-session-1";
    input.extend(frame(request(2, "session/read", Value::object(vec![("sessionId", Value::from(session_id)), ("timeoutMs", Value::from(0_i64))]))));
    input.extend(frame(request(
        3,
        "session/write",
        Value::object(vec![("sessionId", Value::from(session_id)), ("data", Value::from(base64::encode(b"whoami\n").as_str()))]),
    )));
    input.extend(frame(request(4, "session/read", Value::object(vec![("sessionId", Value::from(session_id)), ("timeoutMs", Value::from(0_i64))]))));
    input.extend(frame(request(5, "session/read", Value::object(vec![("sessionId", Value::from(session_id)), ("timeoutMs", Value::from(0_i64))]))));
    input.extend(frame(request(6, "shutdown", Value::Object(vec![]))));

    let messages = run_session(input, FakeModule { with_session: true });
    let responses = responses(&messages);

    let execute = responses[0].get("result").unwrap();
    let sessions = match execute.get("sessions") {
        Some(Value::Array(items)) => items,
        _ => panic!("missing sessions"),
    };
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].get("id").and_then(Value::as_str), Some(session_id));

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
    assert!(text.contains("mock-operator"), "missing whoami output in {text:?}");
}
