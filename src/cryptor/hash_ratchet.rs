use std::{collections::HashMap, sync::Arc};

use napi::Error;
use openmls::{prelude::{aead::{AeadKey, AeadNonce}, secret::Secret, Ciphersuite, OpenMlsProvider}, tree::sender_ratchet::RatchetSecret};
use openmls_rust_crypto::OpenMlsRustCrypto;

/// An implementation of MLS++'s HashRatchet, where each generation is created and cached when requested, using [`RatchetSecret`] internally.
pub struct HashRatchet {
  ratchet: RatchetSecret,
  cache: HashMap<u32, (AeadKey, AeadNonce)>,
  provider: Arc<OpenMlsRustCrypto>,
  ciphersuite: Ciphersuite
}

impl HashRatchet {
  pub fn new(secret: &[u8], provider: Arc<OpenMlsRustCrypto>, ciphersuite: Ciphersuite) -> Self {
    Self {
      ratchet: RatchetSecret::initial_ratchet_secret(Secret::from_slice(secret)),
      cache: HashMap::new(),
      provider,
      ciphersuite
    }
  }

  pub fn get(&mut self, generation: u32) -> napi::Result<&(AeadKey, AeadNonce)> {
    if self.cache.contains_key(&generation) {
      return Ok(self.cache.get(&generation).unwrap())
    }

    if self.ratchet.generation() > generation {
      return Err(Error::from_reason("Tried to request an expired key".to_string()))
    }

    while self.ratchet.generation() <= generation {
      let (next_generation, material) = self.ratchet.ratchet_forward(self.provider.crypto(), self.ciphersuite)
        .map_err(|err| Error::from_reason(format!("Error getting next generation: {err}")))?;
      self.cache.insert(next_generation, material);
    }

    Ok(self.cache.get(&generation).unwrap())
  }

  pub fn erase(&mut self, generation: u32) {
    if self.cache.contains_key(&generation) {
      self.cache.remove(&generation);
    }
  }
}