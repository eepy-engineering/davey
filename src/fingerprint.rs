use napi::{
  bindgen_prelude::{AsyncTask, Buffer},
  Env, Error, Task,
};
use scrypt::{scrypt, Params};

use crate::generate_displayable_code_internal;

const FINGERPRINT_SALT: [u8; 16] = [
  0x24, 0xca, 0xb1, 0x7a, 0x7a, 0xf8, 0xec, 0x2b, 0x82, 0xb4, 0x12, 0xb9, 0x2d, 0xab, 0x19, 0x2e,
];

/// Generate a key fingerprint.
/// @see https://daveprotocol.com/#verification-fingerprint
#[napi]
pub fn generate_key_fingerprint(
  version: u16,
  key: Buffer,
  user_id: String,
) -> napi::Result<Buffer> {
  let user_id = user_id
    .parse::<u64>()
    .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;
  let result = generate_key_fingerprint_internal(version, key.to_vec(), user_id)?;
  Ok(Buffer::from(result))
}

/// Generate a pairwise fingerprint.
/// @see https://daveprotocol.com/#verification-fingerprint
#[allow(dead_code)]
#[napi(ts_return_type = "Promise<Buffer>")]
fn generate_pairwise_fingerprint(
  version: u16,
  key_a: Buffer,
  user_id_a: String,
  key_b: Buffer,
  user_id_b: String,
) -> AsyncTask<AsyncPairwiseFingerprint> {
  AsyncTask::new(AsyncPairwiseFingerprint {
    version,
    key_a,
    user_id_a,
    key_b,
    user_id_b,
  })
}

fn generate_key_fingerprint_internal(
  version: u16,
  key: Vec<u8>,
  user_id: u64,
) -> napi::Result<Vec<u8>> {
  if version != 0 {
    return Err(napi_invalid_arg_error!("Unsupported fingerprint format version"));
  }

  if key.is_empty() {
    return Err(napi_invalid_arg_error!("Key is zero-length"));
  }

  let mut result: Vec<u8> = vec![];
  result.extend(version.to_be_bytes());
  result.extend(key);
  result.extend(user_id.to_be_bytes());
  Ok(result)
}

fn pairwise_fingerprints_internal(mut fingerprints: Vec<Vec<u8>>) -> napi::Result<Vec<u8>> {
  // Similar to compareArrays in libdave/js
  fingerprints.sort_by(|a, b| {
    for i in 0..std::cmp::min(a.len(), b.len()) {
      if a[i] != b[i] {
        return a[i].cmp(&b[i]);
      }
    }

    a.len().cmp(&b.len())
  });

  let params = Params::new(14, 8, 2, 64)
    .map_err(|_| napi_error!("Failed to create scrypt params"))?;

  let mut output = vec![0u8; 64];

  scrypt(
    fingerprints.concat().as_slice(),
    &FINGERPRINT_SALT,
    &params,
    &mut output,
  )
  .map_err(|_| napi_error!("Failed to use scrypt to hash"))?;

  Ok(output)
}

pub struct AsyncPairwiseFingerprint {
  version: u16,
  key_a: Buffer,
  user_id_a: String,
  key_b: Buffer,
  user_id_b: String,
}

impl Task for AsyncPairwiseFingerprint {
  type Output = Vec<u8>;
  type JsValue = Buffer;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    let user_id_a = self
      .user_id_a
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;
    let user_id_b = self
      .user_id_b
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;

    let fingerprints = vec![
      generate_key_fingerprint_internal(self.version, self.key_a.to_vec(), user_id_a)?,
      generate_key_fingerprint_internal(self.version, self.key_b.to_vec(), user_id_b)?,
    ];

    let output = pairwise_fingerprints_internal(fingerprints)?;

    Ok(output)
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(Buffer::from(output))
  }
}

pub struct AsyncPairwiseFingerprintSession {
  pub fingerprints: Option<Vec<Vec<u8>>>,
  pub error: Option<Error>,
}

impl Task for AsyncPairwiseFingerprintSession {
  type Output = Vec<u8>;
  type JsValue = Buffer;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    if self.error.is_some() {
      return Err(self.error.clone().unwrap());
    }

    if self.fingerprints.is_none() {
      return Err(napi_error!("Invalid fingerprints"));
    }

    let output = pairwise_fingerprints_internal(self.fingerprints.clone().unwrap())?;

    Ok(output)
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(Buffer::from(output))
  }
}

pub struct AsyncSessionVerificationCode {
  pub fingerprints: Option<Vec<Vec<u8>>>,
  pub error: Option<Error>,
}

impl Task for AsyncSessionVerificationCode {
  type Output = String;
  type JsValue = String;

  fn compute(&mut self) -> napi::Result<Self::Output> {
    if self.error.is_some() {
      return Err(self.error.clone().unwrap());
    }

    if self.fingerprints.is_none() {
      return Err(napi_error!("Invalid fingerprints"));
    }

    let output = pairwise_fingerprints_internal(self.fingerprints.clone().unwrap())?;
    let code = generate_displayable_code_internal(&output, 45, 5)?;

    Ok(code)
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> napi::Result<Self::JsValue> {
    Ok(output)
  }
}
