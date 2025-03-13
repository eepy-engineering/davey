#![deny(clippy::all)]
#![allow(clippy::upper_case_acronyms)]
use napi::bindgen_prelude::Buffer;
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;

#[macro_use]
extern crate napi_derive;

pub type DAVEProtocolVersion = u16;

mod session;
pub use session::*;

mod fingerprint;
pub use fingerprint::*;

mod displayable_code;
pub use displayable_code::*;

mod cryptor;

// This enables debug statements on debug builds.
#[cfg(debug_assertions)]
#[module_exports]
fn init(mut _exports: napi::JsObject) -> napi::Result<()> {
  env_logger::Builder::new()
    .filter_level(log::LevelFilter::Trace)
    .init();
  Ok(())
}

#[napi(object)]
pub struct SigningKeyPair {
  pub private: Buffer,
  pub public: Buffer,
}

#[napi]
pub fn generate_p256_keypair() -> napi::Result<SigningKeyPair> {
  let signing_key = SigningKey::random(&mut OsRng);

  Ok(SigningKeyPair {
    private: Buffer::from(signing_key.to_bytes().as_slice()),
    public: Buffer::from(
      signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes(),
    ),
  })
}
