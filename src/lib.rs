#![deny(clippy::all)]
use napi::{bindgen_prelude::Buffer, Error};
use openmls::prelude::{Ciphersuite, SignatureScheme};
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;

#[macro_use]
extern crate napi_derive;

mod session;
pub use session::*;

mod fingerprint;
pub use fingerprint::*;

// This enables debubg statements on debug builds.
#[cfg(debug_assertions)]
#[module_exports]
fn init(mut _exports: napi::JsObject) -> napi::Result<()> {
	env_logger::Builder::new().filter_level(log::LevelFilter::Debug).init();
  Ok(())
}

#[napi(object)]
pub struct SigningKeyPair {
	pub private: Buffer,
	pub public: Buffer,
}

#[napi]
pub fn generate_signing_keys(ciphersuite: u16) -> napi::Result<SigningKeyPair> {
	let ciphersuite = Ciphersuite::try_from(ciphersuite as u16)
		.map_err(|err| Error::from_reason(format!("Ciphersuite error: {err}")))?;

	// SignatureKeyPair::new doesn't give us a private key
	match ciphersuite.signature_algorithm() {
		SignatureScheme::ECDSA_SECP256R1_SHA256 => {
			let signing_key = SigningKey::random(&mut OsRng);

			Ok(SigningKeyPair {
				private: Buffer::from(signing_key.to_bytes().as_slice()),
				public: Buffer::from(signing_key.verifying_key().to_encoded_point(false).as_bytes())
			})
		}
		_ => return Err(Error::from_reason("Unsupported signature scheme".to_string())),
	}
}
