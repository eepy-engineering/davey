use std::collections::HashMap;
use napi::Error;
use openmls::{ciphersuite::aead::{AeadKey, AeadNonce}, prelude::{secret::Secret, Ciphersuite, OpenMlsCrypto}, tree::sender_ratchet::RatchetSecret};

pub struct HashRatchet {
  ratchet: RatchetSecret,
  cache: HashMap<u32, (AeadKey, AeadNonce)>
}

/// An implementation of MLS++'s HashRatchet, where each generation is created and cached when requested, using [`RatchetSecret`] internally.
impl HashRatchet {
  pub fn new(secret: &[u8]) -> Self {
    Self {
      ratchet: RatchetSecret::initial_ratchet_secret(Secret::from_slice(secret)),
      cache: HashMap::new()
    }
  }

  pub fn get(&mut self, generation: u32, crypto: &impl OpenMlsCrypto, ciphersuite: Ciphersuite) -> napi::Result<&(AeadKey, AeadNonce)> {
    if self.cache.contains_key(&generation) {
      return Ok(self.cache.get(&generation).unwrap())
    }

    if self.ratchet.generation() > generation {
      return Err(Error::from_reason("Tried to request an expired key".to_string()))
    }

    while self.ratchet.generation() <= generation {
      let (next_generation, material) = self.ratchet.ratchet_forward(crypto, ciphersuite)
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