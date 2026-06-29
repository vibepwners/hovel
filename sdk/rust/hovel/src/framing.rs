//! Length-prefixed JSON-RPC framing over byte streams.

use std::io::{self, BufRead, Write};

use crate::json::{self, Value};

const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// Reads one framed JSON message. Returns `Ok(None)` on a clean end of stream
/// between frames.
pub fn read_message<R: BufRead>(reader: &mut R) -> io::Result<Option<Value>> {
    let mut content_length: Option<usize> = None;
    let mut saw_header = false;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            if !saw_header {
                return Ok(None);
            }
            return Err(frame_error("truncated frame header"));
        }
        saw_header = true;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                let parsed = value
                    .trim()
                    .parse()
                    .map_err(|_| frame_error("invalid Content-Length"))?;
                if parsed > MAX_FRAME_BYTES {
                    return Err(frame_error(&format!(
                        "Content-Length {parsed} exceeds maximum {MAX_FRAME_BYTES}"
                    )));
                }
                content_length = Some(parsed);
            }
        }
    }
    let length = content_length.ok_or_else(|| frame_error("missing Content-Length"))?;
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let text = String::from_utf8(body).map_err(|_| frame_error("invalid UTF-8 frame body"))?;
    let value =
        json::parse(&text).map_err(|err| frame_error(&format!("invalid JSON frame: {err}")))?;
    Ok(Some(value))
}

/// Writes one framed JSON message and flushes the stream.
pub fn write_message<W: Write>(writer: &mut W, message: &Value) -> io::Result<()> {
    let body = message.to_string();
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(body.as_bytes())?;
    writer.flush()
}

fn frame_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("hovel: {message}"))
}
