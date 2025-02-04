import KeySchedule from "./keySchedule";
import RatchetTree from "./ratchetTree";
import type { DAVESession } from "./session";
import { Tree } from "./tree";
import type { DataCursor } from "./util";
import { CipherSuite, ContentType, CredentialType, ExtensionType, LeafNodeSource, MLSLabels, MLSReferenceLabels, ProposalType, ProtocolVersion, SenderType, WireFormat } from "./util/constants";
import { serializeResolvers } from "./util/resolver";
import { Extension, GroupContext } from "./util/types";

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
            extension_data: undefined
          } as any
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
    // TODO: implement the DS
    return group;
  }

  // Normally states have their own ciphersuite, group id, leafnode, and keys, but we *may* not need that
  constructor(session: DAVESession, ratchetTree: RatchetTree, groupContext: GroupContext, keySchedule: KeySchedule) {
    this.#session = session;
    this.#ratchetTree = ratchetTree;
    this.#groupContext = groupContext;
    this.#keySchedule = keySchedule;
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