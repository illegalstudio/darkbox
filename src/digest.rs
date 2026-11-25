//! Lowercase hexadecimal text of digests, as used by inventories and records.

/// The lowercase hexadecimal digits of `bytes`.
pub(crate) fn hex(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[usize::from(byte >> 4)] as char);
        text.push(DIGITS[usize::from(byte & 15)] as char);
    }
    text
}

#[cfg(test)]
mod tests {
    #[test]
    fn hex_is_lowercase_and_zero_padded() {
        assert_eq!(super::hex([0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(super::hex([]), "");
    }
}
