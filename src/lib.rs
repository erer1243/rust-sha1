#![allow(clippy::unreadable_literal)]
#![allow(clippy::many_single_char_names)]

#[cfg(test)]
mod tests;

use std::convert::TryInto;
use std::fs::File;
use std::io::{self, Write};

/// SHA-1 Hash context. Represents one single hash.
///
/// Can be reset and reused, but cannot hash more than one thing at once.
/// Can be cloned if multiple pieces of data share a common prefix.
///
/// Example usage:
/// ```
/// # use sha1::Sha1;
/// # use std::fs::File;
/// # fn f() -> std::io::Result<()> {
/// // Hash some bytes in chunks
/// let mut s = Sha1::new();
/// s.update(b"First part of hashed data");
/// s.update(b"Second part of hashed data");
/// let hash = s.finish();
///
/// // Hash some bytes in one line
/// let hash = Sha1::digest(b"Hello, world");
///
/// // Hash a file in two lines
/// let mut file = File::open("foo.txt")?;
/// let hash = Sha1::digest_file(&mut file);
///
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Sha1 {
    // 512 bit chunk
    chunk: [u8; 64],

    // Bytes currently free in buffer
    used: u8,

    // Number of chunks that have been processed in the past
    chunks_processed: u64,

    // Hash value words
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

impl Sha1 {
    /// Creates a new empty `Sha1` struct.
    pub fn new() -> Sha1 {
        Sha1 {
            chunk: [0; 64],
            used: 0,
            chunks_processed: 0,
            h0: 0x67452301,
            h1: 0xEFCDAB89,
            h2: 0x98BADCFE,
            h3: 0x10325476,
            h4: 0xC3D2E1F0,
        }
    }

    /// Re-initializes internal values to act like a brand new `Sha1` struct.  May be slightly
    /// faster than calling `Sha1::new()` because the internal 64 byte chunk is not zeroed.
    pub fn reset(&mut self) {
        // Does not reset self.chunk because it shouldn't matter
        self.used = 0;
        self.chunks_processed = 0;
        self.h0 = 0x67452301;
        self.h1 = 0xEFCDAB89;
        self.h2 = 0x98BADCFE;
        self.h3 = 0x10325476;
        self.h4 = 0xC3D2E1F0;
    }

    /// Utility function to simplify `Sha1` use when all data is available at once.
    ///
    /// Equivalent to:
    /// ```
    /// # use sha1::Sha1;
    /// # fn f(data: &[u8]) -> [u32; 5] {
    /// let mut s = Sha1::new();
    /// s.update(data);
    /// s.finish()
    /// # }
    /// ```
    pub fn digest<D: AsRef<[u8]>>(data: D) -> [u32; 5] {
        let mut s = Sha1::new();
        s.update(data);
        s.finish()
    }

    /// Utility function to simplify `Sha1` use when hashing a whole file.
    ///
    /// Equivalent to:
    /// ```
    /// # use sha1::Sha1;
    /// # use std::fs::File;
    /// # fn f() -> std::io::Result<([u32; 5], u64)> {
    /// # let mut file = File::open("foo.txt")?;
    /// let mut s = Sha1::new();
    /// let bytes = std::io::copy(&mut file, &mut s)?;
    /// let hash = s.finish();
    /// Ok((hash, bytes))
    /// # }
    pub fn digest_file(file: &mut File) -> io::Result<([u32; 5], u64)> {
        let mut s = Sha1::new();
        let bytes = io::copy(file, &mut s)?;
        let hash = s.finish();
        Ok((hash, bytes))
    }

    /// Adds data to the given hash. Hashing work is done for every 64 bytes passed to the struct
    /// through this function (including from previous calls).
    // This function must always leave at least 1 byte free in the chunk when it's finished.
    pub fn update<D: AsRef<[u8]>>(&mut self, data: D) {
        let data = data.as_ref();

        // Chunk vars
        let mut used = self.used as usize;
        let mut free = 64 - used;

        // Input data vars
        let mut i = 0;
        let mut remaining = data.len();

        // While we can fill the rest of the chunk with the input data,
        // do it and process the chunk once it's full
        while remaining >= free {
            self.chunk[used..64].copy_from_slice(&data[i..i + free]);
            self.process_chunk();

            remaining -= free;
            i += free;
            used = 0;
            free = 64;
        }

        // Fill the chunk as much as possible with remaining input data
        self.chunk[used..used + remaining].copy_from_slice(&data[i..]);
        self.used = (used + remaining) as u8;
    }

    /// Finishes all work for a given hash and returns the final result.
    /// Using a "finished" `Sha1` struct without calling `Sha1::reset()` will
    /// produce incorrect hashes.
    pub fn finish(&mut self) -> [u32; 5] {
        // To finalize the hash, we need to add at least 9 bytes to the next chunk. The 0x80 byte
        // at the end of the message data, and an 8 byte message length.
        let message_length: u64 = self.chunks_processed * 512 + 8 * self.used as u64;

        // Add byte 10000000
        self.chunk[self.used as usize] = 0x80;
        self.used += 1;

        if self.used <= 56 {
            // Fill space between 0x80 and message length with zeros
            for i in self.used..56 {
                self.chunk[i as usize] = 0;
            }
        } else {
            // Fill space between 0x80 and end of chunk with zeroes
            for i in self.used..64 {
                self.chunk[i as usize] = 0;
            }

            // Process the second-to-last chunk
            self.process_chunk();

            // Fill the rest of the space with zeroes
            for i in 0..self.used {
                self.chunk[i as usize] = 0;
            }
        }

        // Add message length bytes
        self.chunk[56..64].copy_from_slice(&message_length.to_be_bytes());

        // Process final chunk
        self.process_chunk();

        [self.h0, self.h1, self.h2, self.h3, self.h4]
    }

    fn process_chunk(&mut self) {
        // Increment chunks_processed, used to compute total message length in finish()
        self.chunks_processed += 1;

        // 80 word buffer
        let mut w = [0u32; 80];

        // Fill first 16 words with data from self.chunk
        for i in 0..16 {
            let word = self.chunk[i * 4..(i + 1) * 4].try_into().unwrap();
            w[i] = u32::from_be_bytes(word);
        }

        // Extend to 80 words using data from first 16
        for i in 16..32 {
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = leftrotate(w[i], 1);
        }

        // Although having the above loop go from 16..80 works,
        // This alternative makes the extension process
        // slightly faster on x86
        for i in 32..80 {
            w[i] = w[i - 6] ^ w[i - 16] ^ w[i - 28] ^ w[i-32];
            w[i] = leftrotate(w[i], 2);
        }

        // Initialize hash value for this chunk
        let mut a = self.h0;
        let mut b = self.h1;
        let mut c = self.h2;
        let mut d = self.h3;
        let mut e = self.h4;

        // Using wrapping_add instead of + prevents overflow panic in debug mode
        // but also produces equivalent code to + in release mode.
        macro_rules! shuffle {
            ($w:expr, $f:expr, $k:expr) => {
                let tmp = leftrotate(a, 5)
                    .wrapping_add($f)
                    .wrapping_add(e)
                    .wrapping_add($k)
                    .wrapping_add($w);
                e = d;
                d = c;
                c = leftrotate(b, 30);
                b = a;
                a = tmp;
            };
        }

        // Do some hashing...
        for &w in &w[0..20] {
            let f = (b & c) | ((!b) & d);
            shuffle!(w, f, 0x5A827999);
        }

        for &w in &w[20..40] {
            let f = b ^ c ^ d;
            shuffle!(w, f, 0x6ED9EBA1);
        }

        for &w in &w[40..60] {
            let f = (b & c) | (b & d) | (c & d);
            shuffle!(w, f, 0x8F1BBCDC);
        }

        for &w in &w[60..80] {
            let f = b ^ c ^ d;
            shuffle!(w, f, 0xCA62C1D6);
        }

        self.h0 = self.h0.wrapping_add(a);
        self.h1 = self.h1.wrapping_add(b);
        self.h2 = self.h2.wrapping_add(c);
        self.h3 = self.h3.wrapping_add(d);
        self.h4 = self.h4.wrapping_add(e);
    }
}

impl Write for Sha1 {
    /// Writes all data to hasher by calling `self.update(data)` and returns `Ok(data.len())`.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.update(data);
        Ok(data.len())
    }

    /// Does nothing and returns `Ok(())`. There is nothing that flush would make sense to do.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn leftrotate(word: u32, bits: u8) -> u32 {
    (word << bits) | (word >> (32 - bits))
}
