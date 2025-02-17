import { expect, test } from 'bun:test';
import { generateSigningKeys } from '../index.js';

test("return valid keys", () => {
  const result = generateSigningKeys(2);
  expect(result).toContainAllKeys(['public', 'private']);
  expect(result.private).toBeInstanceOf(Buffer);
  expect(result.public).toBeInstanceOf(Buffer);
});

test("throws on invalid ciphersuite", () => {
  expect(() => generateSigningKeys(0)).toThrowError();
});

