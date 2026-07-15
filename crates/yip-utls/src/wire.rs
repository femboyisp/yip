/// A length-prefix-aware byte writer for TLS wire structures. `*_prefixed`
/// reserves the length, runs the closure, then backfills the exact body length
/// — so a length can never desync from its body.
pub struct HelloWriter {
    buf: Vec<u8>,
}

impl HelloWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn u16_prefixed(&mut self, f: impl FnOnce(&mut Self)) {
        let at = self.buf.len();
        self.u16(0);
        f(self);
        let len = u16::try_from(self.buf.len() - at - 2).expect("section fits u16");
        self.buf[at..at + 2].copy_from_slice(&len.to_be_bytes());
    }

    pub fn u8_prefixed(&mut self, f: impl FnOnce(&mut Self)) {
        let at = self.buf.len();
        self.u8(0);
        f(self);
        let len = u8::try_from(self.buf.len() - at - 1).expect("section fits u8");
        self.buf[at] = len;
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for HelloWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u16_prefixed_backfills_length() {
        let mut w = HelloWriter::new();
        w.u16_prefixed(|w| {
            w.bytes(&[0xAA, 0xBB, 0xCC]);
        });
        assert_eq!(w.into_bytes(), vec![0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }
    #[test]
    fn u8_prefixed_backfills_length() {
        let mut w = HelloWriter::new();
        w.u8_prefixed(|w| {
            w.bytes(&[0x01, 0x02]);
        });
        assert_eq!(w.into_bytes(), vec![0x02, 0x01, 0x02]);
    }
}
