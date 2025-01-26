import { MinimalKeyPackage, NodeData, RatchetTree } from "./ratchetTree";
import type { DAVESession } from "./session";
import { Tree } from "./tree";
import type { DataCursor } from "./util";
import { CipherSuite, ContentType, CredentialType, LeafNodeSource, MLSLabels, MLSReferenceLabels, ProposalType, ProtocolVersion, SenderType, WireFormat } from "./util/constants";
import { serializeResolvers } from "./util/serialize";

export class MLSState {
  epoch = 0n;
  tree: RatchetTree;
  confirmedTranscriptHash?: Buffer;

  // Normally states have their own ciphersuite, group id, leafnode, and keys, but we *may* not need that
  constructor(private session: DAVESession) {
    this.tree = new RatchetTree(
      session.ciphersuite.type,
      0,
      new Tree<NodeData>([
        new NodeData(undefined, session.hpkePub!, [], session.credentialIdentity, undefined, 0),
      ]),
      [
        new MinimalKeyPackage(session.leafnode!)
      ]
    );
  }

  // TODO form mls message

  // TODO createGroupContext
  #createGroupContext(epoch: bigint, treeHash: Buffer, confirmedTranscriptHash: Buffer) {
    // https://www.rfc-editor.org/rfc/rfc9420.html#section-8.1
    return serializeResolvers([
      ['u16', ProtocolVersion.MLS10],          // version
      ['u16', this.session.ciphersuite.type],  // cipher_suite
      this.session.groupId,                    // group_id
      ['u64', epoch],                          // epoch
      ['v', treeHash],                         // tree_hash
      ['v', confirmedTranscriptHash],          // confirmed_transcript_hash
      ['v'],                                   // TODO extensions
    ]);

    // struct {
    //   ProtocolVersion version = mls10;
    //   CipherSuite cipher_suite;
    //   opaque group_id<V>;
    //   uint64 epoch;
    //   opaque tree_hash<V>;
    //   opaque confirmed_transcript_hash<V>;
    //   Extension extensions<V>;
    // } GroupContext;

  }

  commit() {
    const initialGroupContext = this.#createGroupContext(
      this.epoch,
      this.tree.calculateTreeHash(),
      this.confirmedTranscriptHash!
      // this.extensions,
    );
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

    const groupIdMatches = !this.session.groupId.find((v, i) => groupId[i] !== v);
    if (!groupIdMatches) throw new Error('Public message is not for this group');
    if (this.epoch !== epoch) throw new Error(`Public message is not for this epoch (${this.epoch} != ${epoch})`);

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
    if (ciphersuite !== this.session.ciphersuite.type)
      throw new Error(`Unexpected cipher suite in key package: ${ciphersuite}`);

    const initKey = cursor.readVector();
    const { signatureKey, credentialIdentity } = await this.#validateLeafNode(cursor);
    const extensions = cursor.readVector();
    const endIndex = cursor.index;
    const signature = cursor.readVector();

    const verified = await this.session.ciphersuite.verifyWithLabel(
      signatureKey, MLSLabels.KEY_PACKAGE_TBS, signature, cursor.buffer.subarray(startIndex, endIndex)
    );
    if (!verified) throw new Error('Key package not verified');

    const ref = this.session.ciphersuite.refHash(MLSReferenceLabels.KEY_PACKAGE_REFERENCE, cursor.buffer.subarray(startIndex, cursor.index));
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

    const verified = await this.session.ciphersuite.verifyWithLabel(
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

    if (capabilitiesCipherSuites.length !== 2 || capabilitiesCipherSuites.readInt16BE() !== this.session.ciphersuite.type)
      throw new Error('Unexpected cipher suites in leaf node capabilities');

    if (capabilitiesCredentials.length !== 2 || capabilitiesCredentials.readInt16BE() !== CredentialType.BASIC)
      throw new Error('Unexpected credentials in leaf node capabilities');
  }
}