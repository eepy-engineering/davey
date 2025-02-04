const TYPE_LENGTH_MAP = {
  u8: 1,
  u16: 2,
  u32: 4,
  u64: 8
}

type UIntResolver = [type: 'u8' | 'u16' | 'u32', value: number];
type BigUIntResolver = [type: 'u64', value: bigint];
type VectorResolver = [type: 'v', value?: BufferOrResolvables | undefined];
type OptionalResolver = [type: 'o', value?: BufferOrResolvables | undefined];
type AnyResolver = UIntResolver | BigUIntResolver | VectorResolver | OptionalResolver;
export type Resolvable = AnyResolver | Uint8Array | Buffer;
export type BufferOrResolvables = Uint8Array | Buffer | Resolvable[];

export function getBufferOrResolvableLength(r: BufferOrResolvables | undefined) {
  return  r ? Array.isArray(r) ? r.reduce((p, r) => p + getResolverLength(r), 0) : r.length : 0;
}

export function getResolverLength(r: Resolvable): number {
  if (r instanceof Uint8Array || r instanceof Buffer) return r.length;
  if (r[0] === 'v') {
    const srcLength = getBufferOrResolvableLength(r[1]);
    const lengthBytes = srcLength > 16383 ? 4 : srcLength > 63 ? 2 : 1;
    return lengthBytes + srcLength;
  } else if (r[0] === 'o') {
    return (r[1] ? getBufferOrResolvableLength(r[1]) : 0) + 1;
  }
  else return TYPE_LENGTH_MAP[r[0]];
}

export function serializeResolvers(resolvers: Resolvable[]) { 
  const length = resolvers.reduce((p, r) => p + getResolverLength(r), 0);
  const buffer = Buffer.alloc(length);

  let offset = 0;

  function copyBufferOrResolver(resolver: BufferOrResolvables) {
    if (Array.isArray(resolver)) {
      const src = serializeResolvers(resolver);
      src.copy(buffer, offset);
      offset += src.length;
    } else {
      if (resolver instanceof Buffer) resolver.copy(buffer, offset);
      else buffer.set(resolver, offset);
      offset += resolver.length;
    }
  }


  for (const resolver of resolvers) {
    if (resolver instanceof Uint8Array || resolver instanceof Buffer) {
      if (resolver instanceof Buffer) resolver.copy(buffer, offset);
      else buffer.set(resolver, offset);
      offset += resolver.length;
      continue;
    }
    switch (resolver[0]) {
      case 'u8': {
        buffer.writeUInt8(resolver[1], offset);
        offset += TYPE_LENGTH_MAP[resolver[0]];
        break;
      }
      case 'u16': {
        buffer.writeUInt16BE(resolver[1], offset);
        offset += TYPE_LENGTH_MAP[resolver[0]];
        break;
      }
      case 'u32': {
        buffer.writeUInt32BE(resolver[1], offset);
        offset += TYPE_LENGTH_MAP[resolver[0]];
        break;
      }
      case 'u64': {
        buffer.writeBigUInt64BE(resolver[1], offset);
        offset += TYPE_LENGTH_MAP[resolver[0]];
        break;
      }
      case 'v': {
        const srcLength = getBufferOrResolvableLength(resolver[1]);
        const lengthBytes = srcLength > 16383 ? 4 : srcLength > 63 ? 2 : 1;
        switch (lengthBytes) {
            case 1:
              buffer.writeUInt8(srcLength, offset);
              break;
            case 2:
              buffer.writeUInt16BE(srcLength, offset);
              buffer[offset]! += 0x40;
              break;
            case 4:
              buffer.writeUInt32BE(srcLength, offset);
              buffer[offset]! += 0x80;
              break;
        }
        offset += lengthBytes;
        if (resolver[1]) copyBufferOrResolver(resolver[1]);
        break;
      }
      case 'o': {
        buffer.writeUInt8(resolver[1] ? 1 : 0, offset++);
        if (resolver[1]) copyBufferOrResolver(resolver[1]);
      }
    }
  }

  return buffer;
}