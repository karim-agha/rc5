//! # RC5 Cipher implementation
//!
//! This algorithm is described in this paper:
//! https://www.grc.com/r&d/rc5.pdf

use {
  crate::cipher::{encrypt_block, expand_key},
  cipher::decrypt_block,
  error::Error,
  secrecy::{ExposeSecret, SecretVec, Zeroize},
  std::mem::size_of,
  word::Word,
};

pub mod cipher;
pub mod error;
pub mod word;

/// RC5 Context
///
/// This struct holds the expanded key and the number of rounds that the
/// algorithm will use. Use this struct if you are going to encrypt or
/// decrypt multiple buffers of data with the same key.
///
/// Otherwise you can use the shorthand free standing functions encrypt and
/// decrypt.
pub struct Context<W: Word = u32> {
  pub expanded_key: SecretVec<W>,
  pub rounds: usize,
}

impl<W: Word> Context<W> {
  pub fn new(mut key: Vec<u8>, rounds: usize) -> Result<Self, Error> {
    let expanded_key = expand_key::<W>(&key, rounds)?;
    key.zeroize();

    Ok(Self {
      expanded_key: SecretVec::new(expanded_key),
      rounds,
    })
  }

  /// Encrypts bytes using the RC5 context and returns the ciphertext.
  /// The plaintext must be a multiple of the block size. Padding is not
  /// implemented.
  pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let word_bytes = size_of::<W>();
    let block_size = 2 * word_bytes;

    if plaintext.len() % block_size != 0 {
      return Err(Error::InvalidInputLength);
    }

    let mut ciphertext = Vec::new();
    for block in plaintext.chunks(block_size) {
      let block = [
        W::from_le_bytes(&block[0..word_bytes])?,
        W::from_le_bytes(&block[word_bytes..block_size])?,
      ];

      ciphertext.extend(
        encrypt_block::<W>(self.expanded_key.expose_secret(), block)?
          .into_iter()
          .map(|w| w.to_le_bytes())
          .flatten(),
      );
    }

    Ok(ciphertext)
  }

  pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let word_bytes = size_of::<W>();
    let block_size = 2 * word_bytes;

    if ciphertext.len() % block_size != 0 {
      return Err(Error::InvalidInputLength);
    }

    let mut plaintext = Vec::new();
    for block in ciphertext.chunks(block_size) {
      let block = [
        W::from_le_bytes(&block[0..word_bytes])?,
        W::from_le_bytes(&block[word_bytes..block_size])?,
      ];

      plaintext.extend(
        decrypt_block::<W>(self.expanded_key.expose_secret(), block)?
          .into_iter()
          .map(|w| w.to_le_bytes())
          .flatten(),
      );
    }

    Ok(plaintext)
  }
}

/// Given a key and plaintext, returns the ciphertext using a parametrized RC5.
///
/// This is the generic RC5 implementation, which uses a generic word size and
/// rounds count.
///
/// The word size is specified by using a type parameter, which must implement
/// Word trait. The key size is specified by the length of the key slice.
/// The rounds count is specified by the rounds parameter.
///
/// Usage example:
///
/// ```
/// use rc5::encrypt;
/// let key = [
///   0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10,
///   0x48, 0x81, 0xFF, 0x48,
/// ];
///
/// let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
/// let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
/// let res = encrypt::<u32>(&key, &pt, 12).unwrap();
/// assert_eq!(ct, res);
/// ```
pub fn encrypt<W: Word>(
  key: &[u8],
  plaintext: &[u8],
  rounds: usize,
) -> Result<Vec<u8>, Error> {
  Context::<W>::new(key.to_vec(), rounds)?.encrypt(plaintext)
}

/// Given a key and ciphertext, returns the plaintext using a parametrized RC5.
///
/// This is the generic RC5 implementation, which uses a generic word size and
/// rounds count.
///
/// The word size is specified by using a type parameter, which must implement
/// Word trait. The key size is specified by the length of the key slice.
/// The rounds count is specified by the rounds parameter.
///
/// Usage example:
///
/// ```
/// use rc5::decrypt;
/// let key = [
///   0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10,
///   0x48, 0x81, 0xFF, 0x48,
/// ];
///
/// let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
/// let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
/// let res = decrypt::<u32>(&key, &ct, 12).unwrap();
/// assert_eq!(pt, res);
/// ```
pub fn decrypt<W: Word>(
  key: &[u8],
  ciphertext: &[u8],
  rounds: usize,
) -> Result<Vec<u8>, Error> {
  Context::<W>::new(key.to_vec(), rounds)?.decrypt(ciphertext)
}

/// Given a key and plaintext, return the ciphertext using RC5/32/12/16.
///
/// This is the default RC5 implementation, which uses 32-bit words and 12
/// rounds and a key size of 16 bytes.
///
/// Usage example:
///
/// ```
/// use rc5::encrypt_default;
/// let key = [
///   0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10,
///   0x48, 0x81, 0xFF, 0x48,
/// ];
///
/// let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
/// let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
/// let res = encrypt_default(key, &pt).unwrap();
/// assert_eq!(ct, res);
/// ```
pub fn encrypt_default(
  key: [u8; 16],
  plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
  encrypt::<u32>(&key, plaintext, 12)
}

/// Given a key and ciphertext, return the plaintext using RC5/32/12/16
///
/// Usage example:
///
/// ```
/// use rc5::decrypt_default;
/// let key = [
///   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
///   0x0C, 0x0D, 0x0E, 0x0F,
/// ];
///
/// let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
/// let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
/// let res = decrypt_default(key, &ct).unwrap();
/// assert_eq!(pt, res);
/// ```
pub fn decrypt_default(
  key: [u8; 16],
  ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
  decrypt::<u32>(&key, ciphertext, 12)
}
