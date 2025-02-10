import { CipherSuiteInterface } from "./ciphersuite";
import { CredentialType, ProtocolVersion, LeafNodeSource, ExtensionType, SenderType, ContentType, ProposalOrRefType, ProposalType } from "./constants";
import { Resolvable, serializeResolvers } from "./resolver";
import { Capabilities, Commit, Credential, Extension, FramedContent, GroupContext, KeyPackage, LeafNode, LeafNodeCommit, LeafNodeKeyPackage, Proposal, Sender, UpdatePath } from "./types";

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3 */
export function serializeCredential(credential: Credential) {
  return serializeResolvers([
    // credential_type
    ['u16', credential.credential_type],
  
    // [basic] identity (usually user_id) / [x509] certificates
    ['v', credential.credential_type === CredentialType.BASIC ? credential.identity : credential.credentials.map((cred) => cred.cert_data)]
  ]);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2-2 */
export function serializeCapabilities(capabilities: Capabilities) {
  return serializeResolvers([
    ['v', capabilities.versions.map((n) => (['u16', n]))],      // versions
    ['v', capabilities.cipher_suites.map((n) => (['u16', n]))], // cipher_suites
    ['v', capabilities.extensions.map((n) => (['u16', n]))],    // extensions
    ['v', capabilities.proposals.map((n) => (['u16', n]))],     // proposals
    ['v', capabilities.credentials.map((n) => (['u16', n]))],   // credentials
  ]);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2-2 */
export function serializeLeafNode(leafnode: LeafNode) {
  if (!leafnode.signature) throw new Error('LeafNode must have a signature')
  return serializeResolvers([
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
    ['v', leafnode.signature], // signature
  ]);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-10-6 */
export function serializeKeyPackage(keyPackage: KeyPackage) {
  if (!keyPackage.signature) throw new Error('KeyPackage must have a signature')
  return serializeResolvers([
    ['u16', keyPackage.version],             // protocol_version
    ['u16', keyPackage.cipher_suite],        // cipher_suite
    ['v', keyPackage.init_key],              // init_key
    serializeLeafNode(keyPackage.leaf_node), // leafnode
    ['v', ],                                 // extensions
    ['v', keyPackage.signature],             // signature
  ]);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2 */
export function serializeExtension(extension: Extension<ExtensionType>) {
  return serializeResolvers([
    // extension_type
    ['u16', extension.extension_type],
    // extension_data
    ['v', extension.extension_data instanceof Uint8Array || !extension.extension_data ? extension.extension_data : extension.extension_type === ExtensionType.REQUIRED_CAPABILITIES ? [
      ['v', extension.extension_data.credential_types.map((v) => ['u16', v])],
      ['v', extension.extension_data.proposal_types.map((v) => ['u16', v])],
      ['v', extension.extension_data.credential_types.map((v) => ['u16', v])]
    ] : undefined]
  ]);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-8.1 */
export function serializeGroupContext(groupContext: GroupContext) {
  return serializeResolvers([
    ['u16', groupContext.version],                 // version
    ['u16', groupContext.cipher_suite],            // cipher_suite
    ['v', groupContext.group_id],                  // group_id
    ['u64', groupContext.epoch],                   // epoch
    ['v', groupContext.tree_hash],                 // tree_hash
    ['v', groupContext.confirmed_transcript_hash], // confirmed_transcript_hash
    ['v', groupContext.extensions.map((e) => serializeExtension(e))], // extensions
  ]);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-6-4 */
export function serializeSender(sender: Sender) {
  return serializeResolvers([
    ['u8', sender.sender_type],
    ...(sender.sender_type === SenderType.MEMBER
      ? [['u32', sender.leaf_index]] as Resolvable[]
      : sender.sender_type === SenderType.EXTERNAL
        ? [['u32', sender.sender_index]] as Resolvable[]
        : []
    )
  ]);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.6 */
export function serializeUpdatePath(path: UpdatePath) {
  return serializeResolvers([
    serializeLeafNode(path.leaf_node),
    ['v', path.nodes.map((n) => ([
      ['v', n.encryption_key],
      ['v', n.encrypted_path_secret.kem_output],
      ['v', n.encrypted_path_secret.ciphertext],
    ] as Resolvable[])).reduce((p, v) => ([...p, ...v]), [])]
  ]);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-12.1 */
export function serializeProposal(proposal: Proposal) {
  return serializeResolvers([
    ['u8', proposal.proposal_type],
    ...(proposal.proposal_type === ProposalType.ADD
      ? [serializeKeyPackage(proposal.key_package)] as Resolvable[]
      : [['u32', proposal.removed]] as Resolvable[]
    )
  ]);
}

/** https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4-3 */
export function serializeCommit(commit: Commit) {
  return serializeResolvers([
    ['v', commit.proposals.map((p) => {
      if (p.type === ProposalOrRefType.PROPOSAL)
        return [
          ['u8', p.type],
          serializeProposal(p.proposal)
        ] as Resolvable[];
      else
        return [
          ['u8', p.type],
          ['v', p.reference]
        ] as Resolvable[];
    }).reduce((p, v) => ([...p, ...v]), [])],
    ['o', commit.path ? serializeUpdatePath(commit.path) : undefined]
  ]);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-6-4 */
export function serializeFramedContent(content: FramedContent) {
  return serializeResolvers([
    ['v', content.group_id],
    ['u64', content.epoch],
    serializeSender(content.sender),
    ['u8', content.content_type],
    ['v', content.authenticated_data],
    content.content_type === ContentType.COMMIT ? serializeCommit(content.commit) : serializeProposal(content.proposal)
  ]);
}