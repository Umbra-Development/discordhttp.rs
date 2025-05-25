use flate2::{Decompress, FlushDecompress};
use std::io::{self, Error, ErrorKind};
pub struct ZlibStreamDecompressor {
    decompressor: Decompress,
    buffer: Vec<u8>, // Buffer to store decompressed data
    last_out: usize, // Last index of valid decompressed data in `self.buffer`
}

impl ZlibStreamDecompressor {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            decompressor: Decompress::new(true),
            buffer: vec![0; buffer_size],
            last_out: 0,
        }
    }

    pub fn decompress(&mut self, bytes: &[u8]) -> io::Result<String> {
        match self
            .decompressor
            .decompress(bytes, &mut self.buffer, FlushDecompress::Sync)
        {
            Ok(_status) => {
                // Append only the valid part of the decompressed data to `self.buffer`
                let bytes_written = self.decompressor.total_out() as usize;
                let diff = bytes_written - self.last_out;
                let decompressed_chunk = &self.buffer[..diff];
                self.last_out = bytes_written;

                Ok(std::str::from_utf8(decompressed_chunk).unwrap().to_string())
            }
            Err(e) => Err(io::Error::new(ErrorKind::InvalidData, e)),
        }
    }
}
