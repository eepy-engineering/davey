import ArrayTree, { type IndexedType } from "./arrayTree";
import { toUint32 } from "./util";
import { CipherSuiteInterface } from "./util/ciphersuite";

interface SecretRatchet {
    generation: number;
    secret: Uint8Array;
}
type SecretTreeLeaf = { handshake_ratchet: SecretRatchet; application_ratchet: SecretRatchet };
type SecretTreeNode = Uint8Array | SecretTreeLeaf;

interface MessageSecret {
    key: Uint8Array;
    nonce: Uint8Array;
    generation: number;
}
type MessageSecretReturn<T extends number | undefined> = T extends number ? MessageSecret[] : MessageSecret;

export type { MessageSecret };

const leftLabel = new TextEncoder().encode("left");
const rightLabel = new TextEncoder().encode("right");
const treeLabel = new TextEncoder().encode("tree");
const handshakeLabel = new TextEncoder().encode("handshake");
const applicationLabel = new TextEncoder().encode("application");
const keyLabel = new TextEncoder().encode("key");
const nonceLabel = new TextEncoder().encode("nonce");
const secretLabel = new TextEncoder().encode("secret");

export default class SecretTree extends ArrayTree<SecretTreeNode> {
    #cipherSuite: CipherSuiteInterface;

    constructor(leafCount: number, cipherSuite: CipherSuiteInterface) {
        super(leafCount);
        this.#cipherSuite = cipherSuite;
    }

    async #calculateLeafSecret(node: IndexedType<SecretTreeNode>, cipherSuite: CipherSuiteInterface) {
      if (this.level(node) !== 0)
        throw new Error("Node is not a leaf");
      if (node.data instanceof Uint8Array)
        return node.data;
      // calculate the leaf secret by going down from the root to the leaf node and performing the KDF for each parent node
      const parentSecretNodes = this.directPath(node)
        .reverse()
        .filter((n) => n.data != null);
      if (parentSecretNodes.length !== 0)
        throw new Error("No parent secret nodes, unable to calculate leaf secret");
      for (const parent of parentSecretNodes) {
        const secret = this.getIndexedNode(parent.index).data as Uint8Array;
        if (secret == null) 
          throw new Error("Parent secret is null");
        const leftSecret = await cipherSuite.expandWithLabel(secret, treeLabel, leftLabel, cipherSuite.kdf.hashSize);
        const rightSecret = await cipherSuite.expandWithLabel(secret, treeLabel, rightLabel, cipherSuite.kdf.hashSize);
        this.setNode(parent.left().index, leftSecret);
        this.setNode(parent.right().index, rightSecret);
        this.setNode(node.index, undefined);
      }
      // now we should have the leaf secret
      return this.getIndexedNode(node.index).data as Uint8Array;
    }

    async getMessageSecret<T extends number | undefined>(
      node: IndexedType<SecretTreeNode>,
      type: "handshake" | "application",
      cipherSuite: CipherSuiteInterface,
      until: T
    ): Promise<MessageSecretReturn<T>> {
        // check if we only have the secret, not the ratchets
        let nodeSecret = node.data;
        if (nodeSecret == null)
          nodeSecret = await this.#calculateLeafSecret(node, cipherSuite);
        if (nodeSecret instanceof Uint8Array) {
            // calculate the ratchets
            const handshake_secret = await cipherSuite.expandWithLabel(
              nodeSecret,
              handshakeLabel,
              new Uint8Array(0),
              cipherSuite.kdf.hashSize
            );
            const application_secret = await cipherSuite.expandWithLabel(
              nodeSecret,
              applicationLabel,
              new Uint8Array(0),
              cipherSuite.kdf.hashSize
            );
            this.setNode(node.index, {
              handshake_ratchet: { generation: 0, secret: handshake_secret },
              application_ratchet: { generation: 0, secret: application_secret }
            } satisfies SecretTreeLeaf);
        }
        // we should have the ratchets now
        const ratchets = this.getIndexedNode(node.index).data as SecretTreeLeaf;
        const ratchet = type === "handshake" ? ratchets.handshake_ratchet : ratchets.application_ratchet;
        const generateUntil = until ?? ratchet.generation + 1;
        // do until validation: it must not be less than the current generation
        if (generateUntil < ratchet.generation)
          throw new Error("Generate until is less than the current generation");
        const secrets = new Array<MessageSecret>();
        for (let i = ratchet.generation; i <= generateUntil; i++) {
          const nonce = await cipherSuite.expandWithLabel(
            ratchet.secret,
            nonceLabel,
            toUint32(i),
            cipherSuite.aead.nonceSize
          );
          const key = await cipherSuite.expandWithLabel(
            ratchet.secret,
            keyLabel,
            toUint32(i),
            cipherSuite.aead.keySize
          );
          secrets.push({ key, nonce, generation: i });
          const newSecret = await cipherSuite.expandWithLabel(
            ratchet.secret,
            secretLabel,
            toUint32(i),
            cipherSuite.kdf.hashSize
          );
          ratchet.secret = newSecret;
        }
        ratchet.generation = generateUntil;
        if (type === "handshake") ratchets.handshake_ratchet = ratchet;
        else ratchets.application_ratchet = ratchet;
        this.setNode(node.index, ratchets);
        return <MessageSecretReturn<T>>secrets;
    }

    static fromLength(leafCount: number, cipherSuite: CipherSuiteInterface) {
      const tree = new SecretTree(leafCount, cipherSuite);
      return tree;
    }
}
