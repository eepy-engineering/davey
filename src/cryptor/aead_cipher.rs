use aes_gcm::{aead::AeadMutInPlace, Aes128Gcm, KeyInit};
use napi::Error;

pub struct AeadCipher {
  key: Aes128Gcm,
}

impl AeadCipher {
  pub fn new(key: &[u8]) -> napi::Result<Self> {
    Ok(Self {
      key: Aes128Gcm::new_from_slice(key)
        .map_err(|err| Error::from_reason(format!("AeadCipher initialization error: {err}")))?
    })
  }

  pub fn encrypt(&mut self, buffer: &mut [u8], nonce: &[u8], aad: &[u8]) -> napi::Result<Vec<u8>> {
    let tag = self.key.encrypt_in_place_detached(nonce.into(), aad, buffer)
      .map_err(|err| Error::from_reason(format!("AeadCipher encrypt error: {err}")))?;
    Ok(tag.to_vec())
  }

  pub fn decrypt(&mut self, buffer: &mut [u8], nonce: &[u8], aad: &[u8], tag: &[u8]) -> napi::Result<()> {
    self.key.decrypt_in_place_detached(nonce.into(), aad, buffer, tag.into())
      .map_err(|err| Error::from_reason(format!("AeadCipher decrypt error: {err}")))?;
    Ok(())
  }
}