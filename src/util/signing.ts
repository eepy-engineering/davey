import { CipherSuiteInterface } from "./ciphersuite";
import { ContentType, LeafNodeSource, MLSLabels, ProtocolVersion, SenderType, WireFormat } from "./constants";
import { Resolvable, serializeResolvers } from "./resolver";
import { serializeCapabilities, serializeCredential, serializeFramedContent, serializeGroupContext, serializeLeafNode } from "./serializers";
import { FramedContent, FramedContentAuthData, GroupContext, KeyPackage, LeafNode, LeafNodeCommit, LeafNodeKeyPackage } from "./types";


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

interface SignFramedContentOptions {
  framed_content: FramedContent;
  wire_format: WireFormat;
  signature_key: Uint8Array;
  ciphersuite: CipherSuiteInterface;
  group_context?: GroupContext;
  confirmation_key?: Uint8Array | undefined;
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-6.1 */
export async function signFramedContent({ framed_content, wire_format, signature_key, ciphersuite, group_context, confirmation_key }: SignFramedContentOptions) {
  if ((framed_content.sender.sender_type === SenderType.MEMBER || framed_content.sender.sender_type === SenderType.NEW_MEMBER_COMMIT) && !group_context)
    throw new Error('group_context is required for this FramedContent');
  if (framed_content.content_type === ContentType.COMMIT && !confirmation_key)
    throw new Error('confirmation_key is required for this FramedContent');

  const contentTBS = serializeResolvers([
    ['u16', ProtocolVersion.MLS10],           // version
    ['u16', wire_format],                     // wire_format
    serializeFramedContent(framed_content),   // content
    ['v', framed_content.authenticated_data], // authenticated_data
    ...(framed_content.sender.sender_type === SenderType.MEMBER || framed_content.sender.sender_type === SenderType.NEW_MEMBER_COMMIT ? [
      serializeGroupContext(group_context!)
    ] : [])
  ]);

  const signature = await ciphersuite.signWithLabel(signature_key, MLSLabels.FRAMED_CONTENT_TBS, contentTBS)
  const confirmation_tag = framed_content.content_type === ContentType.COMMIT ? await ciphersuite.mac(confirmation_key!, group_context!.confirmed_transcript_hash) : undefined;

  return { signature, confirmation_tag } satisfies FramedContentAuthData;
}

interface MACAuthenticatedContentOptions {
  framed_content: FramedContent;
  wire_format: WireFormat;
  auth: FramedContentAuthData;
  ciphersuite: CipherSuiteInterface;
  membership_key: Uint8Array;
  group_context?: GroupContext;
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-6.2-3 */
export async function macAuthenticatedContent({ framed_content, wire_format, auth, membership_key, ciphersuite, group_context }: MACAuthenticatedContentOptions) {
  if ((framed_content.sender.sender_type === SenderType.MEMBER || framed_content.sender.sender_type === SenderType.NEW_MEMBER_COMMIT) && !group_context)
    throw new Error('group_context is required for this FramedContent');

  const contentTBS = serializeResolvers([
    ['u16', ProtocolVersion.MLS10],           // version
    ['u16', wire_format],                     // wire_format
    serializeFramedContent(framed_content),   // content
    ['v', framed_content.authenticated_data], // authenticated_data
    ...(framed_content.sender.sender_type === SenderType.MEMBER || framed_content.sender.sender_type === SenderType.NEW_MEMBER_COMMIT ? [
      serializeGroupContext(group_context!)
    ] : [])
  ]);

  const contentTBM = serializeResolvers([
    contentTBS,
    ['v', auth.signature],
    ...(auth.confirmation_tag ? [['v', auth.confirmation_tag]] as Resolvable[] : [])
  ]);

  return await ciphersuite.mac(membership_key, contentTBM);
}