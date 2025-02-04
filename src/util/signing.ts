import { CipherSuiteInterface } from "./ciphersuite";
import { LeafNodeSource, MLSLabels } from "./constants";
import { Resolvable, serializeResolvers } from "./resolver";
import { serializeCapabilities, serializeCredential, serializeLeafNode } from "./serializers";
import { KeyPackage, LeafNode, LeafNodeCommit, LeafNodeKeyPackage } from "./types";


/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2-2 */
export async function signLeafNode(leafnode: LeafNode, ciphersuite: CipherSuiteInterface, groupId?: Uint8Array, leafIndex?: number) {
  if (!leafnode.private_key) throw new Error('LeafNode must have a private_key');
  if (leafnode.leaf_node_source === LeafNodeSource.UPDATE || leafnode.leaf_node_source === LeafNodeSource.COMMIT) {
    if (!groupId) throw new Error('group_id is required for this leafnode');
    if (!leafIndex) throw new Error('leaf_index is required for this leafnode');
  }

  const content = serializeResolvers([
    ['v', leafnode.encryption_key], // encryption_key
    ['v', leafnode.signature_key],  // signature_key

    serializeCredential(leafnode.credential), // credential

    serializeCapabilities(leafnode.capabilities), // capabilities

    ['u8', leafnode.leaf_node_source], // leaf_node_source

    ...(leafnode.leaf_node_source === LeafNodeSource.KEY_PACKAGE ? [
      // lifetime
      ['u64', (leafnode as LeafNodeKeyPackage).lifetime.not_before], // not_before
      ['u64', (leafnode as LeafNodeKeyPackage).lifetime.not_after],  // not_after
    ] as Resolvable[] : leafnode.leaf_node_source === LeafNodeSource.COMMIT ? [
      ['v', (leafnode as LeafNodeCommit).parent_hash] // parent_hash
    ] as Resolvable[] : []),

    ['v', ], // extensions

    ...(leafnode.leaf_node_source === LeafNodeSource.UPDATE || leafnode.leaf_node_source === LeafNodeSource.COMMIT ? [
      ['v', groupId],      // group_id
      ['u32', leafIndex],  // leaf_index
    ] as Resolvable[] : [])
  ]);

  return await ciphersuite.signWithLabel(leafnode.private_key, MLSLabels.LEAF_NODE_TBS, content);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-10-6 */
export async function signKeyPackage(keyPackage: KeyPackage, ciphersuite: CipherSuiteInterface) {
  const content = serializeResolvers([
    ['u16', keyPackage.version],             // protocol_version
    ['u16', keyPackage.cipher_suite],        // cipher_suite
    ['v', keyPackage.init_key],              // init_key
    serializeLeafNode(keyPackage.leaf_node), // leafnode
    ['v'],                                   // extensions
  ]);

  return await ciphersuite.signWithLabel(keyPackage.leaf_node.private_key!, MLSLabels.KEY_PACKAGE_TBS, content);
}