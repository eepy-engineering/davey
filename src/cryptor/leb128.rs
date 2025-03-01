// const LEB128_MAX_SIZE = 10

pub fn leb128_size(value: u64) -> usize {
  let mut size: usize = 0;
  let mut value = value.clone();
  while value >= 0x80 {
    size += 1;
    value >>= 7;
  }
  size + 1
}

pub fn read_leb128(read_at: &mut &[u8]) -> u64 {
  let mut value: u64 = 0;
  let mut fill_bits = 0;
  while !read_at.is_empty() && fill_bits < 64 - 7 {
    let leb_128_byte = read_at[0];
    value |= (leb_128_byte as u64 & 0x7F) << fill_bits;
    *read_at = &read_at[1..];
    fill_bits += 7;
    if (leb_128_byte & 0x80) == 0 {
      return value;
    }
  }
  // Read 9 bytes and didn't find the terminator byte. Check if 10th byte
  // is that terminator, however to fit result into u64 it may carry only
  // single bit.
  if !read_at.is_empty() && read_at[0] <= 1 {
    value |= (read_at[0] as u64) << fill_bits;
    *read_at = &read_at[1..];
    return value;
  }
  // Failed to find terminator leb128 byte.
  *read_at = &[];
  0
}

pub fn write_leb128(mut value: u64, buffer: &mut [u8]) -> usize {
  let mut size = 0;
  while value >= 0x80 {
    buffer[size] = 0x80 | (value & 0x7F) as u8;
    size += 1;
    value >>= 7;
  }
  buffer[size] = value as u8;
  size += 1;
  size
}