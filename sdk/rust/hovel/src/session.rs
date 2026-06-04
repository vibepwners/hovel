//! Interactive sessions a module can open during `run`.

use std::collections::VecDeque;
use std::io;

use crate::json::Value;

/// Identifies an interactive session to the daemon and the operator.
#[derive(Clone, Debug)]
pub struct SessionRef {
    pub id: String,
    pub run_id: String,
    pub module_id: String,
    pub target: String,
    pub name: String,
    pub kind: String,
    pub state: String,
    pub transport: String,
    pub capabilities: Vec<String>,
}

impl SessionRef {
    pub(crate) fn to_value(&self) -> Value {
        Value::object(vec![
            ("id", Value::Str(self.id.clone())),
            ("runId", Value::Str(self.run_id.clone())),
            ("moduleId", Value::Str(self.module_id.clone())),
            ("target", Value::Str(self.target.clone())),
            ("name", Value::Str(self.name.clone())),
            ("kind", Value::Str(self.kind.clone())),
            ("state", Value::Str(self.state.clone())),
            ("transport", Value::Str(self.transport.clone())),
            (
                "capabilities",
                Value::Array(self.capabilities.iter().cloned().map(Value::Str).collect()),
            ),
        ])
    }
}

/// How a session is presented to the operator.
#[derive(Clone, Debug)]
pub struct SessionOptions {
    pub name: String,
    pub kind: String,
    pub transport: String,
    pub capabilities: Vec<String>,
}

impl Default for SessionOptions {
    fn default() -> SessionOptions {
        SessionOptions {
            name: String::new(),
            kind: "shell".to_string(),
            transport: "stdio".to_string(),
            capabilities: vec!["read".to_string(), "write".to_string(), "close".to_string()],
        }
    }
}

impl SessionOptions {
    /// Sets the operator-facing display name.
    pub fn with_name(mut self, name: &str) -> SessionOptions {
        self.name = name.to_string();
        self
    }

    /// Advertises what the operator may do with the session.
    pub fn with_capabilities(mut self, capabilities: &[&str]) -> SessionOptions {
        self.capabilities = capabilities.iter().map(|c| c.to_string()).collect();
        self
    }
}

/// An interactive channel a module opens during `run`, such as a shell. The
/// daemon drives it on the operator's behalf via read/write/close. Most modules
/// use [`LineShellSession`] instead of implementing this directly.
pub trait Session {
    /// Called once when the session is registered.
    fn open(&mut self) -> io::Result<()>;
    /// Delivers operator input to the session.
    fn write(&mut self, data: &[u8]) -> io::Result<()>;
    /// Returns the next chunk of session output, or empty when none is ready.
    fn read(&mut self, wait_ms: i64) -> io::Result<Vec<u8>>;
    /// Terminates the session.
    fn close(&mut self, reason: &str) -> io::Result<()>;
    /// Reports whether the session has terminated.
    fn closed(&self) -> bool;
}

/// A ready-made [`Session`] for modules that answer newline-delimited commands.
/// The built-in commands `exit` and `logout` close the session.
pub struct LineShellSession {
    pub prompt: String,
    pub echo: bool,
    handler: Box<dyn FnMut(&str) -> String + Send>,
    buffer: Vec<u8>,
    queue: VecDeque<Vec<u8>>,
    closed: bool,
}

impl LineShellSession {
    /// Builds a line shell whose `handler` maps a command line to its output.
    pub fn new<F>(prompt: &str, echo: bool, handler: F) -> LineShellSession
    where
        F: FnMut(&str) -> String + Send + 'static,
    {
        LineShellSession {
            prompt: if prompt.is_empty() { "$ ".to_string() } else { prompt.to_string() },
            echo,
            handler: Box::new(handler),
            buffer: Vec::new(),
            queue: VecDeque::new(),
            closed: false,
        }
    }

    fn emit(&mut self, data: Vec<u8>) {
        if !self.closed {
            self.queue.push_back(data);
        }
    }

    fn handle_line(&mut self, command: &str) {
        match command {
            "exit" | "logout" => {
                self.closed = true;
                return;
            }
            "" => {
                let prompt = self.prompt.clone();
                self.emit(prompt.into_bytes());
                return;
            }
            _ => {}
        }
        let mut output = (self.handler)(command);
        if !output.is_empty() {
            if !output.ends_with('\n') {
                output.push('\n');
            }
            self.emit(output.into_bytes());
        }
        if !self.closed {
            let prompt = self.prompt.clone();
            self.emit(prompt.into_bytes());
        }
    }
}

impl Session for LineShellSession {
    fn open(&mut self) -> io::Result<()> {
        let prompt = self.prompt.clone();
        self.emit(prompt.into_bytes());
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        if self.echo && !data.is_empty() {
            self.emit(data.to_vec());
        }
        self.buffer.extend_from_slice(data);
        while let Some(idx) = self.buffer.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=idx).collect();
            let text = String::from_utf8_lossy(&line);
            let command = text.trim_end_matches(['\r', '\n']).trim().to_string();
            self.handle_line(&command);
        }
        Ok(())
    }

    fn read(&mut self, _wait_ms: i64) -> io::Result<Vec<u8>> {
        Ok(self.queue.pop_front().unwrap_or_default())
    }

    fn close(&mut self, _reason: &str) -> io::Result<()> {
        self.closed = true;
        Ok(())
    }

    fn closed(&self) -> bool {
        self.closed
    }
}
