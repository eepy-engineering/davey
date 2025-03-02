use std::time::Instant;

use log::warn;

use crate::cryptor::{codec_utils::validate_encrypted_frame, frame_processors::{serialize_unencrypted_ranges, unencrypted_ranges_size}, leb128::*, *};

use super::{aead_cipher::AeadCipher, cryptor_manager::compute_wrapped_generation, frame_processors::OutboundFrameProcessor, hash_ratchet::HashRatchet, Codec, MediaType, RATCHET_GENERATION_SHIFT_BITS};

pub struct Encryptor {
  ratchet: Option<HashRatchet>,
  cryptor: Option<AeadCipher>,
  current_key_generation: u32,
  truncated_nonce: u32,
  frame_processors: Vec<OutboundFrameProcessor>,
}

impl Encryptor {
  pub fn new() -> Self {
    Self {
      ratchet: None,
      cryptor: None,
      current_key_generation: 0,
      truncated_nonce: 0,
      frame_processors: Vec::new(),
    }
  }

  pub fn set_key_ratchet(&mut self, ratchet: HashRatchet) {
    self.ratchet = Some(ratchet);
    self.cryptor = None;
    self.current_key_generation = 0;
    self.truncated_nonce = 0;
  }

  // TODO use results to propogate errors up and return properly
  pub fn encrypt(&mut self, media_type: MediaType, ssrc: u32, frame: &[u8], encrypted_frame: &mut [u8], bytes_written: &mut usize) -> bool {
    if media_type != MediaType::AUDIO && media_type != MediaType::VIDEO {
      warn!("encryption failed, invalid media type {:?}", media_type);
      return false;
    }

    if self.ratchet.is_none() {
      warn!("encryption failed, no ratchet");
      // stats[this_media_type].encrypt_failure++;
      return false;
    }

    // let start = Instant::now();
    let mut success = true;
    // write the codec identifier
    let codec = self.codec_for_ssrc(ssrc);

    let mut frame_processor = self.get_or_create_frame_processor();
    frame_processor.parse_frame(frame, codec);

    let unencrypted_ranges = &frame_processor.unencrypted_ranges;
    let ranges_size = unencrypted_ranges_size(&unencrypted_ranges);

    let additional_data = &frame_processor.unencrypted_bytes;
    let plaintext_buffer = &frame_processor.encrypted_bytes;

    let frame_size = additional_data.len() + plaintext_buffer.len();
    let tag_buffer_range = frame_size..frame_size + AES_GCM_127_TRUNCATED_TAG_BYTES;

    let mut nonce_buffer = [0u8; AES_GCM_128_NONCE_BYTES];

    const MAX_CIPHERTEXT_VALIDATION_RETRIES: usize = 10;

    // some codecs (e.g. H26X) have packetizers that cannot handle specific byte sequences
    // so we attempt up to MAX_CIPHERTEXT_VALIDATION_RETRIES to encrypt the frame
    // calling into codec utils to validate the ciphertext + supplemental section
    // and re-rolling the truncated nonce if it fails

    // the nonce increment will definitely change the ciphertext and the tag
    // incrementing the nonce will also change the appropriate bytes
    // in the tail end of the nonce
    // which can remove start codes from the last 1 or 2 bytes of the nonce
    // and the two bytes of the unencrypted header bytes
    for attempt in 1..=MAX_CIPHERTEXT_VALIDATION_RETRIES {
      let (curr_cryptor, truncated_nonce) = self.get_next_cryptor_and_nonce();

      if curr_cryptor.is_none() {
        warn!("encryption failed, no cryptor");
        success = false;
        break;
      }

      let curr_cryptor = self.cryptor.as_mut().unwrap();

      nonce_buffer[AES_GCM_128_TRUNCATED_SYNC_NONCE_OFFSET..AES_GCM_128_TRUNCATED_SYNC_NONCE_OFFSET + AES_GCM_128_TRUNCATED_SYNC_NONCE_BYTES]
        .copy_from_slice(&truncated_nonce.to_le_bytes());

      // ciphertext_bytes should be resized properly already
      if frame_processor.ciphertext_bytes.len() != plaintext_buffer.len() {
        warn!("encryption failed, plaintext mismatch (internal error!)");
        success = false;
        break;
      }
      frame_processor.ciphertext_bytes.copy_from_slice(&plaintext_buffer);

      let encrypt_result = curr_cryptor.encrypt(frame_processor.ciphertext_bytes.as_mut_slice(), &nonce_buffer, additional_data);
      if let Ok(tag) = encrypt_result {
        if tag.len() != AES_GCM_127_TRUNCATED_TAG_BYTES {
          warn!("encryption failed, tag size mismatch (got {:?})", tag.len());
          success = false;
          break;
        }
  
        encrypted_frame[tag_buffer_range.clone()].copy_from_slice(&tag);
      } else {
        warn!("encryption failed, aead failed");
        success = false;
        break;
      }

      let reconstructed_frame_size = frame_processor.reconstruct_frame(encrypted_frame);

      let size = leb128_size(truncated_nonce as u64);

      let (truncated_nonce_buffer, rest) = encrypted_frame[frame_size + AES_GCM_127_TRUNCATED_TAG_BYTES..].split_at_mut(size);
      let (unencrypted_ranges_buffer, rest) = rest.split_at_mut(ranges_size as usize);
      let (supplemental_bytes_buffer, marker_bytes_buffer) = rest.split_at_mut(2);

      if write_leb128(truncated_nonce as u64, truncated_nonce_buffer) != size {
        warn!("encryption failed, write_leb128 failed");
        success = false;
        break;
      }

      if serialize_unencrypted_ranges(&unencrypted_ranges, unencrypted_ranges_buffer) != ranges_size {
        warn!("encryption failed, serialize_unencrypted_ranges failed");
        success = false;
        break;
      }

      let supplemental_bytes_large = SUPPLEMENTAL_BYTES + size + ranges_size as usize;
      if supplemental_bytes_large > u16::MAX as usize {
        warn!("encryption failed, supplemental_bytes_large check failed");
        success = false;
        break;
      }

      let supplemental_bytes = supplemental_bytes_large as u16;
      supplemental_bytes_buffer.copy_from_slice(&supplemental_bytes.to_le_bytes());

      marker_bytes_buffer.copy_from_slice(&MARKER_BYTES);

      let encrypted_frame_bytes = reconstructed_frame_size + AES_GCM_127_TRUNCATED_TAG_BYTES + size + ranges_size as usize + 2 + MARKER_BYTES.len();

      if validate_encrypted_frame(&frame_processor, &encrypted_frame[..encrypted_frame_bytes]) {
        *bytes_written = encrypted_frame_bytes;
        break;
      } else if attempt >= MAX_CIPHERTEXT_VALIDATION_RETRIES {
        warn!("encryption failed, reached max validation tries");
        success = false;
        break;
      }
    }

    // FIXME this technically should return when frame_processor drops, but thats gonna be a bit annoying here
    self.return_frame_processor(frame_processor);

    // let now = Instant::now();
    // // stats[this_media_type].encrypt_duration += now.duration_since(start).as_micros();
    // if success {
    //   // stats[this_media_type].encrypt_success++;
    // } else {
    //   // stats[this_media_type].encrypt_failure++;
    // }

    success
  }

  pub fn get_max_ciphertext_byte_size(_media_type: MediaType, frame_size: usize) -> usize {
    return frame_size + SUPPLEMENTAL_BYTES + TRANSFORM_PADDING_BYTES;
  }

  fn get_next_cryptor_and_nonce(&mut self) -> (Option<&AeadCipher>, u32) {
    if self.ratchet.is_none() {
      return (None, 0);
    }

    self.truncated_nonce += 1;
    let generation = compute_wrapped_generation(self.current_key_generation, self.truncated_nonce >> RATCHET_GENERATION_SHIFT_BITS);

    if generation != self.current_key_generation || self.cryptor.is_none() {
      self.current_key_generation = generation;

      let result = self.ratchet.as_mut().unwrap().get(self.current_key_generation);
      match result {
        Ok((key, _)) => {
          let cipher = AeadCipher::new(key.as_slice());
          self.cryptor = cipher.ok();
        },
        Err(err) => {
          warn!("Failed to get cryptor: {:?}", err);
          self.cryptor = None;
        }
      }
    }

    (self.cryptor.as_ref(), self.truncated_nonce)
  }

  fn get_or_create_frame_processor(&mut self) -> OutboundFrameProcessor {
    if self.frame_processors.is_empty() {
      return OutboundFrameProcessor::new();
    }
    self.frame_processors.pop().unwrap()
  }

  fn return_frame_processor(&mut self, frame_processor: OutboundFrameProcessor) {
    self.frame_processors.push(frame_processor);
  }

  fn codec_for_ssrc(&self, _ssrc: u32) -> Codec {
    // TODO ssrc codec pairs...
    Codec::OPUS
  }
}
