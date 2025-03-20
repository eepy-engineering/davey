use aes_gcm::{aead::AeadMutInPlace, aes::Aes128, AesGcm, KeyInit};
use sha2::digest::consts::{U12, U8};

type Aes128GcmModified = AesGcm<Aes128, U12, U8>;

pub struct AeadCipher {
  key: Aes128GcmModified,
}

impl AeadCipher {
  pub fn new(key: &[u8]) -> napi::Result<Self> {
    Ok(Self {
      key: Aes128GcmModified::new_from_slice(key)
        .map_err(|err| napi_error!("AeadCipher initialization error: {err}"))?,
    })
  }

  pub fn encrypt(&mut self, buffer: &mut [u8], nonce: &[u8], aad: &[u8]) -> napi::Result<Vec<u8>> {
    let tag = self
      .key
      .encrypt_in_place_detached(nonce.into(), aad, buffer)
      .map_err(|err| napi_error!("AeadCipher encrypt error: {err}"))?;
    Ok(tag.to_vec())
  }

  pub fn decrypt(
    &mut self,
    buffer: &mut [u8],
    nonce: &[u8],
    aad: &[u8],
    tag: &[u8],
  ) -> napi::Result<()> {
    self
      .key
      .decrypt_in_place_detached(nonce.into(), aad, buffer, tag.into())
      .map_err(|err| napi_error!("AeadCipher decrypt error: {err}"))?;
    Ok(())
  }
}
