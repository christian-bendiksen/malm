use std::io::{self, Write};

use malm_types::Digest;
use sha2::{Digest as ShaDigest, Sha256};

/// A domain-separated encoder that hashes every byte.
///
/// With a sink attached, the same bytes are written and hashed so the preimage
/// and digest always use identical framing.
pub(crate) struct Encoder<'a> {
    hasher: Sha256,
    sink: Option<&'a mut dyn Write>,
    error: Option<io::Error>,
}

impl<'a> Encoder<'a> {
    /// Starts a digest-only encoder.
    pub(crate) fn new(domain: &[u8]) -> Self {
        Self::start(domain, None)
    }

    /// Starts an encoder that also writes the preimage to `sink`.
    pub(crate) fn writing(domain: &[u8], sink: &'a mut dyn Write) -> Self {
        Self::start(domain, Some(sink))
    }

    fn start(domain: &[u8], sink: Option<&'a mut dyn Write>) -> Self {
        let mut encoder = Self {
            hasher: Sha256::new(),
            sink,
            error: None,
        };
        encoder.raw(domain);
        encoder.u16(1);
        encoder
    }

    pub(crate) fn finish(self) -> Digest {
        Digest::from_sha256(self.hasher)
    }

    /// Returns the preimage digest or the first sink error.
    pub(crate) fn finish_written(self) -> io::Result<Digest> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(Digest::from_sha256(self.hasher)),
        }
    }

    pub(crate) fn raw(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        if self.error.is_some() {
            return;
        }
        if let Some(sink) = self.sink.as_mut()
            && let Err(error) = sink.write_all(bytes)
        {
            self.error = Some(error);
        }
    }

    pub(crate) fn tag(&mut self, value: u8) {
        self.raw(&[value]);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.raw(&value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.raw(&value.to_be_bytes());
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.u64(malm_types::usize_to_u64(value.len()));
        self.raw(value);
    }

    pub(crate) fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }
}
