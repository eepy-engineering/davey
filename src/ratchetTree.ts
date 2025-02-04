import ArrayTree, { type IndexedType } from "./arrayTree";
import { CipherSuiteInterface } from "./util/ciphersuite";
import { LeafNodeSource, NodeType } from "./util/constants";
import { Resolvable, serializeResolvers } from "./util/resolver";
import { serializeGroupContext, serializeLeafNode } from "./util/serializers";
import { signLeafNode } from "./util/signing";
import { GroupContext, LeafNode, LeafNodeCommit, ParentNode, RatchetTreeNode, UpdatePath, UpdatePathNode } from "./util/types";

function isParentNode(object: unknown): object is ParentNode {
  return (
      typeof object === "object" &&
      object !== null &&
      "encryption_key" in object &&
      object.encryption_key instanceof Uint8Array &&
      "parent_hash" in object &&
      object.parent_hash instanceof Uint8Array &&
      "unmerged_leaves" in object &&
      Array.isArray(object.unmerged_leaves) &&
      object.unmerged_leaves.every((l) => typeof l === "number")
  );
}
function isLeafNode(object: unknown): object is LeafNode {
  return (
      typeof object === "object" &&
      object !== null &&
      "encryption_key" in object &&
      object.encryption_key instanceof Uint8Array &&
      "signature_key" in object &&
      object.signature_key instanceof Uint8Array &&
      "leaf_node_source" in object &&
      typeof object.leaf_node_source === 'number'
  );
}

export default class RatchetTree extends ArrayTree<RatchetTreeNode> {
  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.1 */
  #getParentNodeResolver(parentNode: ParentNode) {
    return [
      ['v', parentNode.encryption_key],                             // encryption_key
      ['v', parentNode.parent_hash],                                // parent_hash
      ['v', parentNode.unmerged_leaves.map((ln) => (['u32', ln]))], // unmerged_leaves
    ] as Resolvable[];
  }

  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8 */
  hash(node: IndexedType<RatchetTreeNode>, cipherSuite: CipherSuiteInterface) {
    // check if node is a leaf
    const isLeaf = node.index % 2 === 0;
    let data: Buffer;

    if (isLeaf) {
      // LeafNodeHashInput
      data = serializeResolvers([
        // leaf_index
        ['u32', node.index],
        // leaf_node
        ['o', node.data ? serializeLeafNode(node.data as LeafNode) : undefined]
      ]);
    } else {
      // ParentNodeHashInput
      data = serializeResolvers([
        // parent_node
        ['o', node.data ? this.#getParentNodeResolver(node.data as ParentNode) : undefined],
        // left_hash
        ['v', this.hash(node.left(), cipherSuite)],
        // right_hash
        ['v', this.hash(node.right(), cipherSuite)],
      ]);
    };

    const treeHashInput = serializeResolvers([
      // node_type
      ['u8', isLeaf ? NodeType.LEAF : NodeType.PARENT],
      data
    ]);

    return cipherSuite.hash(treeHashInput);
  }

  addLeaf(leaf: LeafNode) {
    let firstEmpty = this.firstEmptyLeaf;
    if (firstEmpty === null) this.extend();
    firstEmpty = this.firstEmptyLeaf;
    if (!firstEmpty?.data) throw new Error('No new empty leaves created from extending');
    firstEmpty.data = leaf;
    return firstEmpty;
  }

  resolution(node: IndexedType<RatchetTreeNode>): IndexedType<RatchetTreeNode>[] {
    /*
      The resolution of a node is an ordered list of non-blank nodes that collectively cover all non-blank descendants of the node. The resolution of the root contains the set of keys that are collectively necessary to encrypt to every node in the group. The resolution of a node is effectively a depth-first, left-first enumeration of the nearest non-blank nodes below the node:

      The resolution of a non-blank node comprises the node itself, followed by its list of unmerged leaves, if any.
      The resolution of a blank leaf node is the empty list.
      The resolution of a blank intermediate node is the result of concatenating the resolution of its left child with the resolution of its right child, in that order.
    */
    if (node.data != null) {
      if (isParentNode(node.data)) {
        return [node, ...[...node.data.unmerged_leaves].map(l => this.getIndexedNode(l))];
      } else {
        return [node];
      }
    }
    if (node.index % 2 === 0) return [];
    return [...this.resolution(this.left(node)), ...this.resolution(this.right(node))];
  }

  filteredDirectPath(node: IndexedType<RatchetTreeNode>) {
    /*
      The filtered direct path of a leaf node L is the node's direct path, with any node removed whose child on the copath of L has an empty resolution (keeping in mind that any unmerged leaves of the copath child count toward its resolution). The removed nodes do not need their own key pairs because encrypting to the node's key pair would be equivalent to encrypting to its non-copath child.
    */
    const copathWithEmptyResolution = node.copath().filter(n => this.resolution(n).length === 0);
    return copathWithEmptyResolution.map(n => n.parent());
  }

  /**
   * Compute and set the parent hashes for a given node
   * @param node The starting node
   * @param cipherSuite The ciphersuite to use
   * @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.9-8
   */
  computeParentHashes(node: IndexedType<RatchetTreeNode>, cipherSuite: CipherSuiteInterface) {
    const copath = node.copath();
    const parentHashNodes = this.filteredDirectPath(node).reverse();
    for (let i = 0; i < parentHashNodes.length; i++) {
      const parentHashNode = parentHashNodes[i]!;
      // get the copath child
      const copathChild = copath.find(c => c.parent().index === parentHashNode.index);
      if (copathChild == null) throw new Error("Copath child not found (but should exist)");
      const parentHashNodeData = this.#assertParentNode(parentHashNode);

      let parentHash: Uint8Array | undefined = undefined;
      // don't encode the parent hash if this is the root node
      if (i !== 0) {
        // get the parent hash of the above node in this filtered direct path (which is one index below)
        const nextNode = this.getIndexedNode(parentHashNodes[i - 1]!.index);
        const nextNodeData = this.#assertParentNode(nextNode);
        parentHash = nextNodeData.parent_hash;
      }

      // remove the unmerged leaves before hashing the copatch child
      for (const leaf of parentHashNodeData.unmerged_leaves) {
        const leafNode = this.getIndexedNode(leaf * 2);
        const leafNodePath = leafNode.directPath();
        for (const n of leafNodePath) {
          if (n.data == null) continue;
          const nodeData = this.#assertParentNode(n);
          nodeData.unmerged_leaves = nodeData.unmerged_leaves.filter(l => l !== leaf);
          this.setNode(n.index, nodeData);
        }
      }

      const parentHashInput = serializeResolvers([
        // encryption_key
        ['v', parentHashNodeData.encryption_key],
        // parent_hash
        ['v', parentHash],
        // original_sibling_tree_hash
        ['v', this.hash(copathChild, cipherSuite)],
      ]);

      const newParentHash = cipherSuite.hash(parentHashInput);
      parentHashNodeData.parent_hash = newParentHash;
      this.setNode(parentHashNode.index, parentHashNodeData);
    };
  }

  /**
   * Update the direct path of a given note, and return the UpdatePath object
   */
  async updateDirectPath(leafNode: IndexedType<RatchetTreeNode>, groupContext: GroupContext, cipherSuite: CipherSuiteInterface) {
    // step 1: blank all nodes in the direct path of the node
    const directPath = leafNode.directPath();
    for (const n of directPath) {
      this.setNode(n.index, undefined);
    }
    // step 2: generate a new hpke key pair for the node
    const leafKeyPair = await cipherSuite.generateKeyPair();
    // generate the path secrets
    const suite = cipherSuite;
    const pathSecrets = new Array<Uint8Array>();
    const initialPathSecret = crypto.getRandomValues(new Uint8Array(suite.kdf.hashSize));
    for (const [i, node] of this.filteredDirectPath(leafNode).entries()) {
      pathSecrets[i] = await cipherSuite.deriveSecret(i === 0 ? initialPathSecret : pathSecrets[i - 1]!, new TextEncoder().encode("path"));
      // derive the node key pair using the secret
      const nodeSecret = await cipherSuite.deriveSecret(pathSecrets[i], new TextEncoder().encode("node"));
      const nodeKeyPair = await cipherSuite.deriveKeyPair(nodeSecret);
      const nodeData = this.#assertParentNode(node);
      nodeData.private_key = nodeKeyPair.privateKey;
      nodeData.encryption_key = await cipherSuite.kem.serializePublicKey(nodeKeyPair.publicKey).then(pk => new Uint8Array(pk));
      this.setNode(node.index, nodeData);
    }
    // time to generate parent hashes along the filtered direct path
    await this.computeParentHashes(leafNode, cipherSuite);
    // update this leaf node
    let leafData = this.#assertLeafNode(leafNode);
    leafData = {
      ...leafData,
      private_key: leafKeyPair.privateKey,
      encryption_key: leafKeyPair.publicKey,
      leaf_node_source: LeafNodeSource.COMMIT,
      parent_hash: this.#assertParentNode(leafNode.parent()).parent_hash
    } satisfies LeafNodeCommit;
    // const leafNodeSignatureData = ConstructLeafNodeSignatureData(leafData, groupContext.group_id, Uint32.from(leafNode.index / 2));
    // leafData.signature = await cipherSuite.signWithLabel(
    //   signature_key,
    //   new TextEncoder().encode("LeafNodeTBS"),
    //   leafNodeSignatureData
    // );
    leafData.signature = await signLeafNode(leafData, cipherSuite, groupContext.group_id, leafNode.index / 2);
    this.setNode(leafNode.index, leafData);
    return pathSecrets;
  }

  async encryptPathSecrets(leafNode: IndexedType<RatchetTreeNode>, pathSecrets: Array<Uint8Array>, groupContext: GroupContext, cipherSuite: CipherSuiteInterface) {
    const encryptedPaths = new Array<UpdatePathNode>();
    const encodedGroupContext = serializeGroupContext(groupContext);
    const copath = leafNode.copath();
    for (const [i, parent] of this.filteredDirectPath(leafNode).entries()) {
      const copathChild = copath.find(c => c.parent().index === parent.index);
      if (copathChild == null) {
        throw new Error("Copath child not found (but should exist)");
      }
      const copathResolution = this.resolution(copathChild);
      for (const copathNode of copathResolution) {
        const copathData = this.#assertParentNode(copathNode);
        const { ciphertext, encKey } = await cipherSuite.encryptWithLabel(copathData.encryption_key, "UpdatePathNode", encodedGroupContext, pathSecrets[i + 1]!);
        const updateNode = {
          encryption_key: copathData.encryption_key,
          encrypted_path_secret: {
            kem_output: encKey,
            ciphertext
          }
        } satisfies UpdatePathNode;
        encryptedPaths.push(updateNode);
      }
    }
    return {
      leaf_node: this.#assertLeafNode(leafNode),
      nodes: encryptedPaths
    } satisfies UpdatePath
  }

  clone() {
    return RatchetTree.buildFromNodes(this.nodes);
  }

  #assertLeafNode(node?: IndexedType<RatchetTreeNode>) {
    if (node == null) throw new Error("Node is null");
    if (node.data == null) throw new Error("Node is not a leaf (blank)");
    if (!isLeafNode(node.data)) throw new Error("Node is not a leaf (different type)");
    return node.data;
  }

  #assertParentNode(node?: IndexedType<RatchetTreeNode>) {
    if (node == null) throw new Error("Node is null");
    if (node.data == null) throw new Error("Node is not a parent (blank)");
    if (!isParentNode(node.data)) throw new Error("Node is not a parent (different type)");
    return node.data;
  }

  static buildFromLeaves(leaves: LeafNode[]) {
      const width = ArrayTree.width(leaves.length);
    const tree = new RatchetTree(leaves.length);
    for (let i = 0; i < width; i++) {
      if (i % 2 === 0) {
        const leaf = leaves[i >> 1];
        tree.setNode(i, leaf);
      } else {
        tree.setNode(i, undefined);
      }
    }
    return tree;
  }

  static buildFromNodes(nodes: Array<RatchetTreeNode | undefined>) {
    const tree = new RatchetTree(ArrayTree.reverseWidth(nodes.length));
    for (let i = 0; i < nodes.length; i++) {
      tree.setNode(i, nodes[i]);
    }
    return tree;
  }
}
