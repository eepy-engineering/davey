use napi::bindgen_prelude::*;

const MAX_GROUP_SIZE: u32 = 8;

/// Generate a displayable code.
/// @see https://daveprotocol.com/#displayable-codes
#[napi]
pub fn generate_displayable_code(
  data: Buffer,
  desired_length: u32,
  group_size: u32,
) -> Result<String> {
  if data.len() < desired_length as usize {
    return Err(Error::new(
      Status::InvalidArg,
      "data.byteLength must be greater than or equal to desiredLength".to_string(),
    ));
  }

  if desired_length % group_size != 0 {
    return Err(Error::new(
      Status::InvalidArg,
      "desiredLength must be a multiple of groupSize".to_string(),
    ));
  }

  if group_size > MAX_GROUP_SIZE {
    return Err(Error::new(
      Status::InvalidArg,
      format!("groupSize must be less than or equal to {}", MAX_GROUP_SIZE),
    ));
  }

  generate_displayable_code_internal(&data, desired_length as usize, group_size as usize)
}

pub fn generate_displayable_code_internal(
  data: &[u8],
  desired_length: usize,
  group_size: usize,
) -> Result<String> {
  let group_modulus: u64 = 10u64.pow(group_size as u32);
  let mut result = String::with_capacity(desired_length);

  for i in (0..desired_length).step_by(group_size) {
    let mut group_value: u64 = 0;

    for j in (1..=group_size).rev() {
      let next_byte = data
        .get(i + (group_size - j))
        .ok_or_else(|| Error::from_reason("Out of bounds access from data array".to_string()))?;

      group_value = (group_value << 8) | (*next_byte as u64);
    }

    result.push_str(
      format!(
        "{:0width$}",
        group_value % group_modulus,
        width = group_size
      )
      .as_str(),
    );
  }

  Ok(result)
}
