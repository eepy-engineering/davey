import test from 'ava';

import { generateSigningKeys } from '../index';

test('returns valid keys', (t) => {
  const result = generateSigningKeys(2);
  t.deepEqual(Object.keys(result), ['private', 'public']);
  t.true(Buffer.isBuffer(result.private));
  t.true(Buffer.isBuffer(result.public));
});

test('throws on invalid ciphersuite', (t) => {
  t.throws(() => generateSigningKeys(0));
});

