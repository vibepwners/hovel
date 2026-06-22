//! The execution context passed to [`crate::Module::run`], plus the internal
//! emitter that carries logs and session events back to the daemon.

use std::collections::HashMap;
use std::io::{self, Write};

use crate::framing::write_message;
use crate::json::Value;
use crate::session::{Session, SessionOptions, SessionRef};

pub(crate) struct Scope {
    pub run_id: String,
    pub module_id: String,
    pub target: String,
}

struct ManagedSession {
    sref: SessionRef,
    session: Box<dyn Session>,
}

/// Emitter owns the output stream and the live sessions. It is held by the
/// server and borrowed mutably by [`Context`] for the duration of `run`.
pub(crate) struct Emitter {
    out: Box<dyn Write>,
    sessions: HashMap<String, ManagedSession>,
    counter: u64,
}

impl Emitter {
    pub(crate) fn new(out: Box<dyn Write>) -> Emitter {
        Emitter {
            out,
            sessions: HashMap::new(),
            counter: 0,
        }
    }

    /// Writes a complete JSON-RPC message (a response) to the output stream.
    pub(crate) fn write(&mut self, message: &Value) -> io::Result<()> {
        write_message(&mut self.out, message)
    }

    fn notify(&mut self, method: &str, params: Value) {
        let message = Value::object(vec![
            ("jsonrpc", Value::from("2.0")),
            ("method", Value::from(method)),
            ("params", params),
        ]);
        let _ = write_message(&mut self.out, &message);
    }

    fn log(&mut self, record: Value) {
        self.notify("module/log", record);
    }

    fn fire_session(&mut self, event: &str, sref: &SessionRef, fields: Option<Value>) {
        let mut params = vec![("event", Value::from(event)), ("session", sref.to_value())];
        if let Some(fields) = fields {
            params.push(("fields", fields));
        }
        self.notify("module/session", Value::object(params));
    }

    fn open_session(
        &mut self,
        scope: &Scope,
        mut session: Box<dyn Session>,
        opts: SessionOptions,
    ) -> io::Result<SessionRef> {
        self.counter += 1;
        let id = format!("{}-session-{}", scope.run_id, self.counter);
        let sref = SessionRef {
            id: id.clone(),
            run_id: scope.run_id.clone(),
            module_id: scope.module_id.clone(),
            target: scope.target.clone(),
            name: opts.name,
            kind: opts.kind,
            state: "active".to_string(),
            transport: opts.transport,
            capabilities: opts.capabilities,
        };
        session.open()?;
        self.sessions
            .insert(id.clone(), ManagedSession { sref: sref.clone(), session });
        self.fire_session("session.created", &sref, None);
        Ok(sref)
    }

    pub(crate) fn session_write(&mut self, id: &str, data: &[u8]) -> io::Result<()> {
        let managed = self
            .sessions
            .get_mut(id)
            .ok_or_else(|| unknown_session(id))?;
        managed.session.write(data)
    }

    pub(crate) fn session_read(&mut self, id: &str, wait_ms: i64) -> io::Result<(Vec<u8>, bool)> {
        let (chunk, closed, newly_closed) = {
            let managed = self
                .sessions
                .get_mut(id)
                .ok_or_else(|| unknown_session(id))?;
            let chunk = managed.session.read(wait_ms)?;
            let mut newly_closed = None;
            if managed.session.closed() && managed.sref.state != "closed" {
                managed.sref.state = "closed".to_string();
                newly_closed = Some(managed.sref.clone());
            }
            (chunk, managed.sref.state == "closed", newly_closed)
        };
        if let Some(sref) = newly_closed {
            self.fire_session(
                "session.closed",
                &sref,
                Some(Value::object(vec![("reason", Value::from("closed"))])),
            );
        }
        Ok((chunk, closed))
    }

    pub(crate) fn session_close(&mut self, id: &str, reason: &str) -> io::Result<()> {
        let sref = {
            let managed = self
                .sessions
                .get_mut(id)
                .ok_or_else(|| unknown_session(id))?;
            managed.session.close(reason)?;
            if managed.sref.state == "closed" {
                None
            } else {
                managed.sref.state = "closed".to_string();
                Some(managed.sref.clone())
            }
        };
        if let Some(sref) = sref {
            self.fire_session(
                "session.closed",
                &sref,
                Some(Value::object(vec![("reason", Value::from(reason))])),
            );
        }
        Ok(())
    }

    pub(crate) fn close_all(&mut self) {
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        for id in ids {
            let _ = self.session_close(&id, "shutdown");
        }
    }

    pub(crate) fn refs_for_run(&self, run_id: &str) -> Vec<SessionRef> {
        self.sessions
            .values()
            .filter(|managed| managed.sref.run_id == run_id)
            .map(|managed| managed.sref.clone())
            .collect()
    }
}

fn unknown_session(id: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("hovel: unknown session {id:?}"))
}

/// Everything a module needs for one execution.
pub struct Context<'a> {
    pub run_id: String,
    pub module_id: String,
    pub target: String,
    pub inputs: Value,
    pub chain_config: Value,
    pub target_config: Value,
    pub agent: Option<Value>,
    module_name: String,
    emitter: &'a mut Emitter,
}

impl<'a> Context<'a> {
    pub(crate) fn new(emitter: &'a mut Emitter, module_name: &str, params: &Value) -> Context<'a> {
        let field = |key: &str| params.get(key).and_then(Value::as_str).unwrap_or("").to_string();
        let object = |key: &str| match params.get(key) {
            Some(value @ Value::Object(_)) => value.clone(),
            _ => Value::Object(Vec::new()),
        };
        Context {
            run_id: field("runId"),
            module_id: field("moduleId"),
            target: field("target"),
            inputs: object("inputs"),
            chain_config: object("chainConfig"),
            target_config: object("targetConfig"),
            agent: params.get("agentContext").cloned(),
            module_name: module_name.to_string(),
            emitter,
        }
    }

    /// Resolves a configuration value, preferring per-run inputs, then
    /// target-level config, then chain-level config.
    pub fn input(&self, key: &str) -> Option<Value> {
        for source in [&self.inputs, &self.target_config, &self.chain_config] {
            if let Some(value) = source.get(key) {
                return Some(value.clone());
            }
        }
        None
    }

    /// [`Context::input`] coerced to a string, falling back to `default`.
    pub fn input_str(&self, key: &str, default: &str) -> String {
        match self.input(key) {
            Some(Value::Str(s)) => s,
            Some(Value::Num(n)) => {
                if n.fract() == 0.0 {
                    format!("{}", n as i64)
                } else {
                    format!("{n}")
                }
            }
            Some(Value::Bool(b)) => b.to_string(),
            _ => default.to_string(),
        }
    }

    /// Emits a structured log record at the given level.
    pub fn log(&mut self, level: &str, message: &str, fields: &[(&str, Value)]) {
        let mut members = vec![
            ("level", Value::from(level)),
            ("message", Value::from(message)),
            ("logger", Value::from(self.module_name.as_str())),
        ];
        if !fields.is_empty() {
            members.push((
                "fields",
                Value::Object(fields.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()),
            ));
        }
        self.emitter.log(Value::object(members));
    }

    /// Emits an info-level log record.
    pub fn info(&mut self, message: &str, fields: &[(&str, Value)]) {
        self.log("info", message, fields);
    }

    /// Emits an error-level log record.
    pub fn error(&mut self, message: &str, fields: &[(&str, Value)]) {
        self.log("error", message, fields);
    }

    /// Registers an interactive session opened by the module. The session
    /// outlives `run`: the daemon keeps the process alive and drives it for the
    /// operator.
    pub fn open_session(
        &mut self,
        session: Box<dyn Session>,
        opts: SessionOptions,
    ) -> io::Result<SessionRef> {
        let scope = Scope {
            run_id: self.run_id.clone(),
            module_id: self.module_id.clone(),
            target: self.target.clone(),
        };
        self.emitter.open_session(&scope, session, opts)
    }
}
