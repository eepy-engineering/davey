import KeySchedule from "./keySchedule";
import RatchetTree from "./ratchetTree";
import type { DAVESession } from "./session";
import type { DataCursor } from "./util";
import { CipherSuite, ContentType, CredentialType, ExtensionType, LeafNodeSource, MLSLabels, MLSReferenceLabels, ProposalOrRefType, ProposalType, ProtocolVersion, SenderType, WireFormat } from "./util/constants";
import { macAuthenticatedContent, signFramedContent } from "./util/signing";
import { AddProposal, Commit, FramedContent, GroupContext, Proposal, ProposalOrRefProposal, RemoveProposal, UpdatePath } from "./util/types";

export class MLSState {
  #session: DAVESession;
  #ratchetTree: RatchetTree;
  #groupContext: GroupContext;
  #keySchedule: KeySchedule;
  #leafIndex = 0;

  static async create(session: DAVESession) {
    const ratchetTree = RatchetTree.buildFromLeaves([session.leafnode!]);
    const groupContext = {
        version: ProtocolVersion.MLS10,
        cipher_suite: session.ciphersuite.type,
        group_id: session.groupId,
        epoch: 0n,
        confirmed_transcript_hash: new Uint8Array(0),
        extensions: [
          {
            extension_type: ExtensionType.EXTERNAL_SENDERS,
            extension_data: new Uint8Array(session.externalSender!.buffer)
          }
        ],
        tree_hash: ratchetTree.hash(ratchetTree.root, session.ciphersuite)
    } satisfies GroupContext;
    const epochSecret = crypto.getRandomValues(new Uint8Array(session.ciphersuite.kdf.hashSize));
    const keySchedule = await KeySchedule.fromEpochSecret(epochSecret, session.ciphersuite, 1);
    const group = new MLSState(session, ratchetTree, groupContext, keySchedule);
    const confirmation_key = keySchedule.getSecret("confirmation_key");
    if (confirmation_key == null) throw new Error("Confirmation key not set");
    const confirmation_tag = await session.ciphersuite.mac(confirmation_key, group.#groupContext.confirmed_transcript_hash);
    // compute the interim transcript hash
    await keySchedule.computeInterimTranscriptHash(group.#groupContext.confirmed_transcript_hash, confirmation_tag);
    return group;
  }

  // Normally states have their own ciphersuite, group id, leafnode, and keys, but we *may* not need that
  constructor(session: DAVESession, ratchetTree: RatchetTree, groupContext: GroupContext, keySchedule: KeySchedule) {
    this.#session = session;
    this.#ratchetTree = ratchetTree;
    this.#groupContext = groupContext;
    this.#keySchedule = keySchedule;
  }

  
  #processAddProposal(proposal: AddProposal, ratchetTree: RatchetTree) {
    // add the new leaf node to the tree
    const addedNode = ratchetTree.addLeaf(proposal.key_package.leaf_node);
    // set unmerged_leaves for each non-blank intermediate node along the direct path
    const intermediates = addedNode.directPath().filter(n => n.data != null);
    intermediates.pop();
    for (const node of intermediates) {
      if (node.data == null) continue;
      const nodeData = ratchetTree.assertParentNode(node);
      nodeData.unmerged_leaves.push(addedNode.index / 2);
      // make sure unmerged_leaves is sorted in ascending order
      nodeData.unmerged_leaves.sort((a, b) => a - b);
      ratchetTree.setNode(node.index, nodeData);
    }
  }

  #processRemoveProposal(proposal: RemoveProposal, ratchetTree: RatchetTree) {
    // remove the leaf node from the tree
    ratchetTree.setNode(proposal.removed, undefined);

    // blank all intermediate nodes
    const nodes = this.#ratchetTree.directPath(ratchetTree.getIndexedNode(proposal.removed));
    nodes.pop();
    for (const node of nodes) ratchetTree.setNode(node.index, undefined);

    // Truncate the tree by removing the right subtree until there is at least one non-blank leaf node in the right subtree. If the rightmost non-blank leaf has index L, then this will result in the tree having 2d leaves, where d is the smallest value such that 2^d > L.
    const lastNonBlankLeaf = ratchetTree.lastNonBlankLeaf;
    if (!lastNonBlankLeaf) throw new Error("No non-blank leaf nodes");
    const leafIndex = lastNonBlankLeaf.index / 2;
    let d = 0;
    while (leafIndex >= (1 << d)) d++;
    while (ratchetTree.leafCount !== (1 << d)) ratchetTree.truncate();
  }

  async applyProposals(proposals: Proposal[]) {
    const newRatchetTree = this.#ratchetTree.clone();

    // apply remove proposals
    const removeProposals = proposals.filter((p) => p.proposal_type === ProposalType.REMOVE);
    for (const proposal of removeProposals) this.#processRemoveProposal(proposal as RemoveProposal, newRatchetTree);
  
    // apply add proposals
    const addProposals = proposals.filter((p) => p.proposal_type === ProposalType.ADD);
    for (const proposal of addProposals) this.#processAddProposal(proposal as AddProposal, newRatchetTree);

    this.#ratchetTree = newRatchetTree;
  }

  async createCommit(proposals: Proposal[], signature_key: Uint8Array) {
    const newRatchetTree = this.#ratchetTree.clone();
    const ciphersuite = this.#session.ciphersuite;
    let newGroupContext = {
      ...this.#groupContext,
      epoch: this.#groupContext.epoch + 1n
    } satisfies GroupContext;
    await this.applyProposals(proposals);
    const shouldPopulatePath = proposals.some((p) => p.proposal_type === ProposalType.REMOVE);
    let path: UpdatePath | undefined = undefined;
    let commit_secret: Uint8Array | undefined = undefined;

    // perform the direct path update, if needed
    if (shouldPopulatePath) {
      const pathSecrets = await newRatchetTree.updateDirectPath(newRatchetTree.getIndexedNode(this.#leafIndex / 2), this.#groupContext, ciphersuite);
      commit_secret = await ciphersuite.deriveSecret(pathSecrets.at(-1) as Uint8Array, new TextEncoder().encode("path"));
      newGroupContext.tree_hash = newRatchetTree.hash(newRatchetTree.root, ciphersuite);
      path = await newRatchetTree.encryptPathSecrets(newRatchetTree.getIndexedNode(this.#leafIndex / 2), pathSecrets, newGroupContext, ciphersuite);
    }

    const commit = {
      proposals: proposals.map(p => ({ proposal: p, type: ProposalOrRefType.PROPOSAL } satisfies ProposalOrRefProposal)),
      path
    } satisfies Commit;
    if (!commit_secret) commit_secret = new Uint8Array(ciphersuite.kdf.hashSize).fill(0);

    const framed_content = {
      group_id: this.#groupContext.group_id,
      epoch: this.#groupContext.epoch,
      sender: {
        sender_type: SenderType.MEMBER,
        leaf_index: this.#leafIndex
      },
      content_type: ContentType.COMMIT,
      authenticated_data: new Uint8Array(),
      commit
    } satisfies FramedContent;

    const auth = await signFramedContent({
      framed_content,
      wire_format: WireFormat.MLS_PUBLIC_MESSAGE,
      signature_key,
      ciphersuite,
      confirmation_key: this.#keySchedule.getSecret("confirmation_key")
    });

    const membership_tag = await macAuthenticatedContent({
      framed_content,
      wire_format: WireFormat.MLS_PUBLIC_MESSAGE,
      auth,
      ciphersuite,
      membership_key: this.#keySchedule.getSecret("membership_key")!
    });

    // TODO put it all together
    // TODO welcome also
  }

  // TODO pass recognized user IDs
  async parseMLSMessageProposal(cursor: DataCursor) {
    const protocolVersion: ProtocolVersion = cursor.readU16();
    const wireFormat: WireFormat = cursor.readU16();
  
    if (protocolVersion !== ProtocolVersion.MLS10)
      throw new Error(`Unsupported protocol version: ${protocolVersion}`);
  
    if (wireFormat !== WireFormat.MLS_PUBLIC_MESSAGE)
      throw new Error(`Unsupported wire format: ${wireFormat}`);

    const groupId = cursor.readVector();
    const epoch = cursor.readU64();

    const groupIdMatches = !this.#session.groupId.find((v, i) => groupId[i] !== v);
    if (!groupIdMatches) throw new Error('Public message is not for this group');
    if (this.#groupContext.epoch !== epoch) throw new Error(`Public message is not for this epoch (${this.#groupContext.epoch} != ${epoch})`);

    const senderType: SenderType = cursor.readU8();
    const senderIndex = cursor.readU32();

    if (senderType !== SenderType.EXTERNAL) throw new Error('MLS proposal is not from external sender');

    const authenticatedData = cursor.readVector();
    const contentType: ContentType = cursor.readU8();

    if (contentType !== ContentType.PROPOSAL) throw new Error('parseMLSMessageProposal called with a non-proposal message');

    // Parsing proposal
    const proposalStartIndex = cursor.index;
    const proposalType: ProposalType = cursor.readU16();

    if (proposalType !== ProposalType.ADD && proposalType !== ProposalType.REMOVE)
      throw new Error(`MLS proposal must be add or remove (${proposalType})`);

    // TODO handle removes

    const { credentialIdentity } = await this.#validateKeyPackage(cursor);

    // Extract the proposal from the message for committing
    const proposalBuffer = cursor.buffer.subarray(proposalStartIndex, cursor.index);

    const auth = cursor.readVector();

    // TODO on add, check against list of recognized user IDs in credentialIdentity
  }

  async #validateKeyPackage(cursor: DataCursor) {
    const startIndex = cursor.index;
    const protocolVersion: ProtocolVersion = cursor.readU16();
    if (protocolVersion !== ProtocolVersion.MLS10)
      throw new Error(`Unsupported protocol version in key package: ${protocolVersion}`);

    const ciphersuite: CipherSuite = cursor.readU16();
    if (ciphersuite !== this.#session.ciphersuite.type)
      throw new Error(`Unexpected cipher suite in key package: ${ciphersuite}`);

    const initKey = cursor.readVector();
    const { signatureKey, credentialIdentity } = await this.#validateLeafNode(cursor);
    const extensions = cursor.readVector();
    const endIndex = cursor.index;
    const signature = cursor.readVector();

    const verified = await this.#session.ciphersuite.verifyWithLabel(
      signatureKey, MLSLabels.KEY_PACKAGE_TBS, signature, cursor.buffer.subarray(startIndex, endIndex)
    );
    if (!verified) throw new Error('Key package not verified');

    const ref = this.#session.ciphersuite.refHash(MLSReferenceLabels.KEY_PACKAGE_REFERENCE, cursor.buffer.subarray(startIndex, cursor.index));
    return { credentialIdentity, ref };
  } 

  async #validateLeafNode(cursor: DataCursor) {
    const startIndex = cursor.index;
    const encryptionKey = cursor.readVector();
    const signatureKey = cursor.readVector();

    const credentialType = cursor.readU16();
    const credentialIdentity = cursor.readVector();

    this.#validateCapabilities(cursor);

    const leafNodeSource: LeafNodeSource = cursor.readU8();

    if (leafNodeSource !== LeafNodeSource.KEY_PACKAGE)
      throw new Error('Leaf node source is not key package');

    const notBefore = cursor.readU64();
    const notAfter = cursor.readU64();
    const extensions = cursor.readVector();
    const endIndex = cursor.index;
    const signature = cursor.readVector();

    const verified = await this.#session.ciphersuite.verifyWithLabel(
      signatureKey, MLSLabels.LEAF_NODE_TBS, signature, cursor.buffer.subarray(startIndex, endIndex)
    );
    if (!verified) throw new Error('Leaf node not verified');

    return { signatureKey, credentialIdentity };
  }

  #validateCapabilities(cursor: DataCursor) {
    const capabilitiesVersions = cursor.readVector();
    const capabilitiesCipherSuites = cursor.readVector();
    const capabilitiesExtensions = cursor.readVector();
    const capabilitiesProposals = cursor.readVector();
    const capabilitiesCredentials = cursor.readVector();

    if (capabilitiesVersions.length !== 2 || capabilitiesVersions.readInt16BE() !== ProtocolVersion.MLS10)
      throw new Error('Unexpected versions in leaf node capabilities');

    if (capabilitiesCipherSuites.length !== 2 || capabilitiesCipherSuites.readInt16BE() !== this.#session.ciphersuite.type)
      throw new Error('Unexpected cipher suites in leaf node capabilities');

    if (capabilitiesCredentials.length !== 2 || capabilitiesCredentials.readInt16BE() !== CredentialType.BASIC)
      throw new Error('Unexpected credentials in leaf node capabilities');
  }
}