import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import type { AeadInterface, KemInterface, KdfInterface } from "@hpke/core";
import { secp256r1 } from "@noble/curves/p256";

import crypto, { subtle } from "node:crypto";
import { CipherSuite as CipherSuiteType, LABEL_HEADER } from "./constants";
import { serializeResolvers } from "./serialize";

const EMPTY_BUFFER = new Uint8Array(0);
type KeyPair = crypto.webcrypto.CryptoKeyPair;
type Key = crypto.webcrypto.CryptoKey;
type Algorithm = crypto.webcrypto.AlgorithmIdentifier | crypto.webcrypto.RsaPssParams | crypto.webcrypto.EcdsaParams | crypto.webcrypto.Ed448Params;

export class CipherSuiteInterface extends CipherSuite {
  keyAlgorithm: Algorithm = { name: 'ECDSA', hash: 'SHA-256' }; // p256
  type: CipherSuiteType;

  constructor(ciphersuite: CipherSuiteType) {
    if (ciphersuite !== CipherSuiteType.MLS_128_DHKEMP256_AES128GCM_SHA256_P256) throw new Error('Unsupported ciphersuite');

    let kem = new DhkemP256HkdfSha256();
    let kdf = new HkdfSha256();
    let aead = new Aes128Gcm();
    super({ kem, kdf, aead });
    this.type = ciphersuite;
  }

  generateSigningKeyPair() {
    return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify', 'sign']);
  }

  generateKeyPair() {
    return this.kem.generateKeyPair();
  }

  async deriveKeyPair(secret: Uint8Array) {
    const kp = await this.kem.deriveKeyPair(secret.buffer as ArrayBuffer);
    return {
      privateKey: await this.kem.serializePrivateKey(kp.privateKey).then(sk => new Uint8Array(sk)),
      publicKey: await this.kem.serializePublicKey(kp.publicKey).then(pk => new Uint8Array(pk))
    };
  }

  async #resolvePublicKey(publicKey: Uint8Array | Key) {
    return publicKey instanceof Uint8Array ? await subtle.importKey(
      'raw', publicKey, this.keyAlgorithm, false, ['verify'],
    ) : publicKey;
    // return publicKey instanceof Uint8Array ?  this.kem.deserializePublicKey(publicKey.buffer as ArrayBuffer) : publicKey;
  }

  async #resolvePrivateKey(privateKey: Uint8Array | Key) {
    // TODO auto-detect pkcs8 and raw keys maybe
    return privateKey instanceof Uint8Array ? await subtle.importKey(
      'pkcs8', privateKey, this.keyAlgorithm, false, ['sign'],
    ) : privateKey;
    // return privateKey instanceof Uint8Array ?  this.kem.deserializePrivateKey(privateKey.buffer as ArrayBuffer) : privateKey;
  }

  async #sign(key: Key, message: Uint8Array) {
    return new Uint8Array(await subtle.sign(this.keyAlgorithm, key, message));
  }

  async #verify(key: Key, message: Uint8Array, signature: Uint8Array) {
    return await subtle.verify(this.keyAlgorithm, key, signature, message);
  }

  #hash(data: crypto.BinaryLike) {
    return crypto.createHash('sha256').update(data).digest();
  }

  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2 */
  async verifyWithLabel(publicKey: Uint8Array | Key, label: string, signature: Uint8Array, content: Uint8Array) {
    const signContent = serializeResolvers([
      ['v', Buffer.from(LABEL_HEADER + label)], // label
      ['v', content]                            // content
    ]);
    const key = await this.#resolvePublicKey(publicKey);
    return await this.#verify(key, signContent, signature);
  }

  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2 */
  async signWithLabel(privateKey: Uint8Array | Key, label: string, content: Uint8Array) {
    const signContent = serializeResolvers([
      ['v', Buffer.from(LABEL_HEADER + label)], // label
      ['v', content]                            // content
    ]);
    const key = await this.#resolvePrivateKey(privateKey);
    return this.#sign(key, signContent);
  }
  
  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.3 */
  async encryptWithLabel(publicKey: Uint8Array | Key, label: string, context: Uint8Array, plaintext: Uint8Array) {
    const encryptContext = serializeResolvers([
      ['v', Buffer.from(LABEL_HEADER + label)], // label
      ['v', context]                            // context
    ]);
    const key = await this.#resolvePublicKey(publicKey);

    return this
      .seal(
        {
          recipientPublicKey: key,
          info: encryptContext.buffer as ArrayBuffer
        },
        plaintext.buffer as ArrayBuffer
      )
      .then((r) => ({
        ciphertext: new Uint8Array(r.ct),
        encKey: new Uint8Array(r.enc)
      }));
  }

  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.3 */
  async decryptWithLabel(privateKey: Uint8Array | Key, label: string, context: Uint8Array, kemOutput: Uint8Array, ciphertext: Uint8Array) {
    const encryptContext = serializeResolvers([
      ['v', Buffer.from(LABEL_HEADER + label)], // label
      ['v', context]                            // context
    ]);
    const key = await this.#resolvePrivateKey(privateKey);
    return this
      .open(
        {
          recipientKey: key,
          info: encryptContext.buffer as ArrayBuffer,
          enc: kemOutput.buffer as ArrayBuffer
        },
        ciphertext.buffer as ArrayBuffer
      )
      .then((r) => new Uint8Array(r));
  }

  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-5.2 */
  refHash(label: string, value: Uint8Array) {
    const refHashInput = serializeResolvers([
      ['v', Buffer.from(label)], // label
      ['v', value]               // value
    ]);
    return this.#hash(refHashInput);
  }

  async mac(key: Uint8Array | Key, data: Uint8Array) {
    const cryptoKey = await this.#resolvePrivateKey(key);
    return new Uint8Array(await subtle.sign('HMAC', cryptoKey, data));
  }
  
  async verifyMac(key: Uint8Array | Key, data: Uint8Array, mac: Uint8Array) {
    const cryptoKey = await this.#resolvePublicKey(key);
    return await subtle.verify('HMAC', cryptoKey, mac, data);
  }

  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-8 */
  async expandWithLabel(secret: Uint8Array, label: Uint8Array, context: Uint8Array, length: number) {
    const kdfLabel = serializeResolvers([
      ['u16', length],                          // length
      ['v', Buffer.from(LABEL_HEADER + label)], // label
      ['v', context]                            // context
    ]);

    const result = await this.kdf.expand(secret.buffer as ArrayBuffer, kdfLabel.buffer as ArrayBuffer, length);
    return new Uint8Array(result);
  }

  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-8 */
  async deriveSecret(secret: Uint8Array, label: Uint8Array) {
    return this.expandWithLabel(secret, label, EMPTY_BUFFER, this.kdf.hashSize);
  }
}