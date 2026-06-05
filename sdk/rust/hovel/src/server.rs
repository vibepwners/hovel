//! The JSON-RPC dispatch loop that drives a module over stdin/stdout.

use std::io::{self, BufRead, Write};

use crate::base64;
use crate::context::{Context, Emitter};
use crate::framing::read_message;
use crate::json::Value;
use crate::module::Module;

/// Runs `module` over stdin/stdout until the daemon sends "shutdown" or the
/// stream closes. This is the entry point for every Rust module's `main`:
///
/// ```no_run
/// # struct MyModule;
/// # impl hovel::Module for MyModule {
/// #   fn info(&self) -> hovel::Info { unimplemented!() }
/// #   fn schema(&self) -> hovel::Schema { unimplemented!() }
/// #   fn run(&self, _ctx: &mut hovel::Context) -> hovel::Outcome { unimplemented!() }
/// # }
/// fn main() {
///     hovel::serve(MyModule);
/// }
/// ```
pub fn serve<M: Module>(module: M) {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let out: Box<dyn Write> = Box::new(io::stdout());
    if let Err(err) = serve_with(&module, &mut reader, out) {
        eprintln!("hovel sdk error: {err}");
        std::process::exit(2);
    }
}

/// The testable core of [`serve`]: drives `module` using an arbitrary reader and
/// writer instead of the process's stdio.
pub fn serve_with<R: BufRead>(
    module: &dyn Module,
    reader: &mut R,
    out: Box<dyn Write>,
) -> io::Result<()> {
    let mut emitter = Emitter::new(out);
    loop {
        let message = match read_message(reader)? {
            Some(message) => message,
            None => return Ok(()),
        };
        let method = message.get("method").and_then(Value::as_str).unwrap_or("").to_string();
        if method.is_empty() {
            continue;
        }
        let id = match message.get("id") {
            Some(id) => id.clone(),
            None => continue, // notification: no response expected
        };
        let params = message.get("params").cloned().unwrap_or(Value::Object(Vec::new()));
        let response = match dispatch(module, &mut emitter, &method, &params) {
            Ok(result) => Value::object(vec![
                ("jsonrpc", Value::from("2.0")),
                ("id", id),
                ("result", result),
            ]),
            Err(message) => Value::object(vec![
                ("jsonrpc", Value::from("2.0")),
                ("id", id),
                (
                    "error",
                    Value::object(vec![
                        ("code", Value::from(-32000_i64)),
                        ("message", Value::Str(message)),
                    ]),
                ),
            ]),
        };
        emitter.write(&response)?;
        if method == "shutdown" {
            return Ok(());
        }
    }
}

fn dispatch(
    module: &dyn Module,
    emitter: &mut Emitter,
    method: &str,
    params: &Value,
) -> Result<Value, String> {
    match method {
        "handshake" => Ok(handshake(module)),
        "schema" => Ok(schema(module)),
        "execute" => Ok(execute(module, emitter, params)),
        "session/write" => session_write(emitter, params),
        "session/read" => session_read(emitter, params),
        "session/close" => session_close(emitter, params),
        "shutdown" => {
            emitter.close_all();
            Ok(Value::object(vec![("status", Value::from("ok"))]))
        }
        other => Err(format!("unknown method {other:?}")),
    }
}

fn handshake(module: &dyn Module) -> Value {
    let info = module.info();
    Value::object(vec![
        ("name", Value::Str(info.name)),
        ("version", Value::Str(info.version)),
        ("moduleType", Value::from(info.module_type.as_str())),
        ("summary", Value::Str(info.summary)),
        ("description", Value::Str(info.description)),
        ("tags", Value::Array(info.tags.into_iter().map(Value::Str).collect())),
    ])
}

fn schema(module: &dyn Module) -> Value {
    let schema = module.schema();
    Value::object(vec![
        (
            "chainConfig",
            Value::Array(schema.chain_config.iter().map(|r| r.to_value()).collect()),
        ),
        (
            "targetConfig",
            Value::Array(schema.target_config.iter().map(|r| r.to_value()).collect()),
        ),
        ("outputs", Value::Object(schema.outputs)),
    ])
}

fn execute(module: &dyn Module, emitter: &mut Emitter, params: &Value) -> Value {
    let run_id = params.get("runId").and_then(Value::as_str).unwrap_or("").to_string();
    let outcome = {
        let mut ctx = Context::new(emitter, &module.info().name, params);
        module.run(&mut ctx)
    };
    let refs = emitter.refs_for_run(&run_id);
    outcome.to_value(refs)
}

fn session_write(emitter: &mut Emitter, params: &Value) -> Result<Value, String> {
    let id = params.get("sessionId").and_then(Value::as_str).unwrap_or("");
    let data = params.get("data").and_then(Value::as_str).unwrap_or("");
    let bytes = base64::decode(data)?;
    emitter.session_write(id, &bytes).map_err(|e| e.to_string())?;
    Ok(Value::object(vec![("status", Value::from("ok"))]))
}

fn session_read(emitter: &mut Emitter, params: &Value) -> Result<Value, String> {
    let id = params.get("sessionId").and_then(Value::as_str).unwrap_or("");
    let wait_ms = params.get("timeoutMs").and_then(Value::as_f64).unwrap_or(1000.0) as i64;
    let (chunk, closed) = emitter.session_read(id, wait_ms).map_err(|e| e.to_string())?;
    Ok(Value::object(vec![
        ("sessionId", Value::from(id)),
        ("data", Value::Str(base64::encode(&chunk))),
        ("closed", Value::Bool(closed)),
    ]))
}

fn session_close(emitter: &mut Emitter, params: &Value) -> Result<Value, String> {
    let id = params.get("sessionId").and_then(Value::as_str).unwrap_or("");
    let reason = params.get("reason").and_then(Value::as_str).unwrap_or("closed");
    emitter.session_close(id, reason).map_err(|e| e.to_string())?;
    Ok(Value::object(vec![("status", Value::from("ok"))]))
}
