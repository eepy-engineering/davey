use std::time::Duration;

/** Magic marker ID */
pub const MARKER_BYTES: [u8; 2] = [0xFA, 0xFA];

/** Layout constants */
pub const AES_GCM_128_KEY_BYTES: usize = 16;
pub const AES_GCM_128_NONCE_BYTES: usize = 12;
pub const AES_GCM_128_TRUNCATED_SYNC_NONCE_BYTES: usize = 4;
pub const AES_GCM_128_TRUNCATED_SYNC_NONCE_OFFSET: usize = AES_GCM_128_NONCE_BYTES - AES_GCM_128_TRUNCATED_SYNC_NONCE_BYTES;
pub const RATCHET_GENERATION_BYTES: usize = 1;
pub const AES_GCM_127_TRUNCATED_TAG_BYTES: usize = 8;
pub const RATCHET_GENERATION_SHIFT_BITS: usize = 8 * (AES_GCM_128_TRUNCATED_SYNC_NONCE_BYTES - RATCHET_GENERATION_BYTES);
pub const SUPPLEMENTAL_BYTES: usize = AES_GCM_127_TRUNCATED_TAG_BYTES + 1 + 2;
pub const TRANSFORM_PADDING_BYTES: usize = 64;

/** Timing constants */
pub const CIPHER_EXPIRY: Duration = Duration::new(10, 0);

/** Behavior constants */
pub const MAX_GENERATION_GAP: u32 = 250;
pub const MAX_MISSING_NONCES: u64 = 1000;
pub const GENERATION_WRAP: u32 = 1 << (8 * RATCHET_GENERATION_BYTES);
pub const MAX_FRAMES_PER_SECOND: u64 = 50 + 2 * 60; // 50 audio frames + 2 * 60fps video streams

#[napi]
#[derive(Debug,PartialEq)]
pub enum MediaType {
  Audio = 0,
  Video = 1
}

#[napi]
#[derive(Debug,PartialEq)]
pub enum Codec {
  Unknown = 0,
  Opus = 1,
  Vp8 = 2,
  Vp9 = 3,
  H264 = 4,
  H265 = 5,
  Av1 = 6
}

pub(crate) mod aead_cipher;
pub(crate) mod cryptor_manager;
pub(crate) mod hash_ratchet;
pub(crate) mod encryptor;
pub(crate) mod leb128;
pub(crate) mod frame_processors;
pub(crate) mod codec_utils;