import test from 'ava';

import { generateP256Keypair } from '../index';

test('returns valid keys', (t) => {
  const result = generateP256Keypair();
  t.deepEqual(Object.keys(result), ['private', 'public']);
  t.true(Buffer.isBuffer(result.private));
  t.true(Buffer.isBuffer(result.public));
});

