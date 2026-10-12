use crate::model::{Failure, Result};
use serde_json::{Map, Number, Value};

// Build Value objects explicitly so duplicate keys and arbitrary numeric values
// are preserved correctly, including keys used privately by serde_json itself.
struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Parser<'_> {
    fn error(&self, message: &str) -> Failure {
        Failure::invalid(
            "manifest.json",
            format!("{message} at byte {}", self.position),
        )
    }
    fn space(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.position += 1;
        }
    }
    fn consume(&mut self, byte: u8) -> bool {
        self.space();
        if self.bytes.get(self.position) == Some(&byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }
    fn string(&mut self) -> Result<String> {
        self.space();
        let start = self.position;
        if !self.consume(b'"') {
            return Err(self.error("Expected a JSON string"));
        }
        while let Some(byte) = self.bytes.get(self.position) {
            self.position += 1;
            match byte {
                b'"' => {
                    return serde_json::from_slice(&self.bytes[start..self.position])
                        .map_err(|_| self.error("Invalid JSON string"));
                }
                b'\\' => self.position += 1,
                _ => {}
            }
        }
        Err(self.error("Unterminated JSON string"))
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > 128 {
            return Err(Failure::limit("JSON nesting exceeds 128 levels"));
        }
        self.space();
        match self.bytes.get(self.position).copied() {
            Some(b'{') => {
                self.position += 1;
                let mut object = Map::new();
                if self.consume(b'}') {
                    return Ok(Value::Object(object));
                }
                loop {
                    let key = self.string()?;
                    if object.contains_key(&key) {
                        return Err(self.error("Duplicate JSON object key"));
                    }
                    if !self.consume(b':') {
                        return Err(self.error("Expected ':'"));
                    }
                    object.insert(key, self.value(depth + 1)?);
                    if self.consume(b'}') {
                        break;
                    }
                    if !self.consume(b',') {
                        return Err(self.error("Expected ',' or '}'"));
                    }
                }
                Ok(Value::Object(object))
            }
            Some(b'[') => {
                self.position += 1;
                let mut array = Vec::new();
                if self.consume(b']') {
                    return Ok(Value::Array(array));
                }
                loop {
                    array.push(self.value(depth + 1)?);
                    if self.consume(b']') {
                        break;
                    }
                    if !self.consume(b',') {
                        return Err(self.error("Expected ',' or ']'"));
                    }
                }
                Ok(Value::Array(array))
            }
            Some(b'"') => self.string().map(Value::String),
            Some(b't') | Some(b'f') | Some(b'n') => {
                let (literal, value) = match self.bytes[self.position] {
                    b't' => (b"true".as_slice(), Value::Bool(true)),
                    b'f' => (b"false".as_slice(), Value::Bool(false)),
                    _ => (b"null".as_slice(), Value::Null),
                };
                if self.bytes.get(self.position..self.position + literal.len()) != Some(literal) {
                    return Err(self.error("Invalid JSON literal"));
                }
                self.position += literal.len();
                Ok(value)
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.position;
                while self.bytes.get(self.position).is_some_and(|byte| {
                    matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                }) {
                    self.position += 1;
                }
                let text = std::str::from_utf8(&self.bytes[start..self.position]).unwrap();
                if text.len() > 4096 {
                    return Err(Failure::limit("JSON numeric literal exceeds 4096 bytes"));
                }
                if let Some((_, exponent)) = text.split_once(['e', 'E']) {
                    let magnitude = exponent
                        .trim_start_matches(['+', '-'])
                        .trim_start_matches('0');
                    if magnitude.len() > 4
                        || magnitude.parse::<u32>().is_ok_and(|value| value > 4096)
                    {
                        return Err(Failure::limit(
                            "JSON numeric exponent exceeds magnitude 4096",
                        ));
                    }
                }
                let number = text
                    .parse::<Number>()
                    .map_err(|_| self.error("Invalid JSON number"))?;
                Ok(Value::Number(number))
            }
            _ => Err(self.error("Expected a JSON value")),
        }
    }
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Value> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) || std::str::from_utf8(bytes).is_err() {
        return Err(Failure::invalid(
            "manifest.encoding",
            "JSON must be UTF-8 without a BOM",
        ));
    }
    let mut parser = Parser { bytes, position: 0 };
    let value = parser.value(0)?;
    parser.space();
    if parser.position != bytes.len() {
        return Err(parser.error("Unexpected trailing JSON data"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::parse;
    #[test]
    fn rejects_duplicate_keys_at_every_depth() {
        for input in [r#"{"a":1,"\u0061":2}"#, r#"{"data":[{"a":1,"a":2}]}"#] {
            assert!(parse(input.as_bytes()).is_err());
        }
    }
    #[test]
    fn preserves_json_numbers_and_private_named_objects() {
        let value =
            parse(br#"{"number":1e500,"data":{"$serde_json::private::Number":"ordinary data"}}"#)
                .unwrap();
        assert_eq!(value["number"].to_string(), "1e+500");
        assert_eq!(
            value["data"]["$serde_json::private::Number"],
            "ordinary data"
        );
    }
    #[test]
    fn rejects_non_json_and_trailing_values() {
        for input in [
            "[1,]",
            "{\"a\":1,}",
            "[01]",
            "[-]",
            "[NaN]",
            "true false",
            "/* comment */{}",
            "{\"a\":\"line\nline\"}",
        ] {
            assert!(parse(input.as_bytes()).is_err(), "{input}");
        }
    }
    #[test]
    fn bounds_numeric_arithmetic_before_schema_validation() {
        for input in [
            "1e1000000000".to_string(),
            "1e-4097".to_string(),
            "9".repeat(4097),
        ] {
            assert_eq!(
                parse(input.as_bytes()).unwrap_err().status,
                crate::Status::ResourceLimit
            );
        }
        assert!(parse(b"1e0000000500").is_ok());
    }
}
