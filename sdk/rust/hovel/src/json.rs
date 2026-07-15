//! A tiny, dependency-free JSON value type with a parser and encoder.
//!
//! Real modules usually reach for `serde_json`; this example SDK hand-rolls a
//! minimal JSON layer so the whole crate builds with nothing but the standard
//! library. It supports exactly what the Hovel protocol needs: objects (with
//! insertion order preserved), arrays, strings, numbers, booleans, and null.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Array(Vec<Value>),
    /// Object members in insertion order.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Builds an object from key/value pairs.
    pub fn object(pairs: Vec<(&str, Value)>) -> Value {
        Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// Returns the value for `key` if this is an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Returns the string contents, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the value as a string, defaulting to `default`.
    pub fn str_or<'a>(&'a self, default: &'a str) -> &'a str {
        self.as_str().unwrap_or(default)
    }

    /// Returns the numeric value, if this is a number.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            _ => None,
        }
    }

    /// Returns the boolean value, if this is a bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the array contents, if this is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the object members, if this is an object.
    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(members) => Some(members),
            _ => None,
        }
    }

    fn encode(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Num(n) => {
                if n.fract() == 0.0 && n.is_finite() && n.abs() < 1e15 {
                    let _ = write!(out, "{}", *n as i64);
                } else {
                    let _ = write!(out, "{}", n);
                }
            }
            Value::Str(s) => encode_string(s, out),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.encode(out);
                }
                out.push(']');
            }
            Value::Object(members) => {
                out.push('{');
                for (i, (key, value)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    encode_string(key, out);
                    out.push(':');
                    value.encode(out);
                }
                out.push('}');
            }
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        self.encode(&mut out);
        f.write_str(&out)
    }
}

fn encode_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parses a JSON document, returning the value or an error message.
pub fn parse(input: &str) -> Result<Value, String> {
    let mut parser = Parser {
        chars: input.chars().collect(),
        pos: 0,
    };
    parser.skip_ws();
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != parser.chars.len() {
        return Err("trailing characters after JSON document".to_string());
    }
    Ok(value)
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let ch = self.peek();
        if ch.is_some() {
            self.pos += 1;
        }
        ch
    }

    fn skip_ws(&mut self) {
        while matches!(
            self.peek(),
            Some(' ') | Some('\t') | Some('\n') | Some('\r')
        ) {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        self.skip_ws();
        match self.peek() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => Ok(Value::Str(self.parse_string()?)),
            Some('t') | Some('f') => self.parse_bool(),
            Some('n') => self.parse_null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            other => Err(format!("unexpected token {:?}", other)),
        }
    }

    fn parse_object(&mut self) -> Result<Value, String> {
        self.next(); // consume '{'
        let mut members = Vec::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.next();
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err("expected object key".to_string());
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.next() != Some(':') {
                return Err("expected ':' after object key".to_string());
            }
            let value = self.parse_value()?;
            members.push((key, value));
            self.skip_ws();
            match self.next() {
                Some(',') => continue,
                Some('}') => break,
                other => return Err(format!("expected ',' or '}}', got {:?}", other)),
            }
        }
        Ok(Value::Object(members))
    }

    fn parse_array(&mut self) -> Result<Value, String> {
        self.next(); // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.next();
            return Ok(Value::Array(items));
        }
        loop {
            let value = self.parse_value()?;
            items.push(value);
            self.skip_ws();
            match self.next() {
                Some(',') => continue,
                Some(']') => break,
                other => return Err(format!("expected ',' or ']', got {:?}", other)),
            }
        }
        Ok(Value::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.next(); // consume opening quote
        let mut out = String::new();
        loop {
            match self.next() {
                Some('"') => return Ok(out),
                Some('\\') => match self.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('b') => out.push('\u{0008}'),
                    Some('f') => out.push('\u{000C}'),
                    Some('u') => out.push(self.parse_unicode()?),
                    other => return Err(format!("invalid escape {:?}", other)),
                },
                Some(c) => out.push(c),
                None => return Err("unterminated string".to_string()),
            }
        }
    }

    fn parse_unicode(&mut self) -> Result<char, String> {
        let mut code: u32 = 0;
        for _ in 0..4 {
            let digit = self.next().ok_or("unterminated \\u escape")?;
            let value = digit.to_digit(16).ok_or("invalid \\u escape")?;
            code = code * 16 + value;
        }
        char::from_u32(code).ok_or_else(|| "invalid unicode scalar".to_string())
    }

    fn parse_bool(&mut self) -> Result<Value, String> {
        if self.matches("true") {
            Ok(Value::Bool(true))
        } else if self.matches("false") {
            Ok(Value::Bool(false))
        } else {
            Err("invalid literal".to_string())
        }
    }

    fn parse_null(&mut self) -> Result<Value, String> {
        if self.matches("null") {
            Ok(Value::Null)
        } else {
            Err("invalid literal".to_string())
        }
    }

    fn parse_number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.next();
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit() || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-')
        {
            self.next();
        }
        let text: String = self.chars[start..self.pos].iter().collect();
        text.parse::<f64>()
            .map(Value::Num)
            .map_err(|_| format!("invalid number {:?}", text))
    }

    fn matches(&mut self, literal: &str) -> bool {
        let chars: Vec<char> = literal.chars().collect();
        if self.pos + chars.len() > self.chars.len() {
            return false;
        }
        if self.chars[self.pos..self.pos + chars.len()] == chars[..] {
            self.pos += chars.len();
            true
        } else {
            false
        }
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Value {
        Value::Str(value.to_string())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Value {
        Value::Str(value)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Value {
        Value::Bool(value)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Value {
        Value::Num(value)
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Value {
        Value::Num(value as f64)
    }
}

/// Convenience for building an object `Value` from owned pairs.
pub fn obj(pairs: Vec<(String, Value)>) -> Value {
    Value::Object(pairs)
}

/// Converts a string map into an object value.
pub fn map_to_value(map: &BTreeMap<String, Value>) -> Value {
    Value::Object(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
}
