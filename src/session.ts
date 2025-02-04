import { CipherSuite, CredentialType, LeafNodeSource, ProposalsOperationType, ProtocolVersion } from './util/constants';
import { DataCursor, generateKey, readVarint, serializePublicKey } from './util';
import { MLSState } from './state';
import { CipherSuiteInterface, KeyPair } from './util/ciphersuite';
import { KeyPackage, LeafNodeKeyPackage } from './util/types';
import { signKeyPackage, signLeafNode } from './util/signing';
import { serializeKeyPackage } from './util/serializers';

// NOTE: group id === channel id

export class DAVESession {
  protocolVersion = 0;
  ciphersuite = new CipherSuiteInterface(CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256);

  userId = '';
  credentialIdentity = Buffer.alloc(8);
  groupId = Buffer.alloc(8);

  signingKeys?: KeyPair | undefined;
  hpkeKeys?: KeyPair | undefined;

  leafnode?: LeafNodeKeyPackage | undefined;
  joinInitKeys?: KeyPair | undefined;
  joinKeyPackage?: KeyPackage | undefined;
  externalSender?: Buffer | undefined;

  pendingGroupState?: MLSState | undefined;

  async init(protocolVersion: number, userId: string, groupId: string, transientKey?: KeyPair) {
    this.reset();
    this.protocolVersion = protocolVersion;
    this.userId = userId;
    this.groupId.writeBigUInt64BE(BigInt(groupId));
    this.credentialIdentity.writeBigUInt64BE(BigInt(userId));

    await this.#createLeafNode(transientKey);
    await this.#createPendingGroup();
  }

  reset() {
    console.log('Resetting MLS session');

    this.#clearPendingState();
    
    // currentState_.reset();
    // outboundCachedGroupState_.reset();

    this.protocolVersion = 0;
    this.groupId.fill(0);
    this.credentialIdentity.fill(0);
  }

  #clearPendingState() {
    this.pendingGroupState = undefined;
    // pendingGroupState_.reset();
    // pendingGroupCommit_.reset();

    this.joinInitKeys = undefined;
    this.joinKeyPackage = undefined;

    this.hpkeKeys = undefined;
    this.leafnode = undefined;

    // stateWithProposals_.reset();
    // proposalQueue_.clear();
  }

  setExternalSender(externalSender: Buffer) {
    // if (currentState_) {
    //     DISCORD_LOG(LS_ERROR) << "Cannot set external sender after joining/creating an MLS group";
    //     return;
    // }

    console.log('Unmarshalling MLS external sender');

    // DISCORD_LOG(LS_INFO) << "Sender: " << ::mlspp::bytes_ns::bytes(marshalledExternalSender);

    this.externalSender = externalSender;
    // externalSender_ = std::make_unique<::mlspp::ExternalSender>(
    //   ::mlspp::tls::get<::mlspp::ExternalSender>(marshalledExternalSender));

    if (!this.#groupIdEmpty()) this.#createPendingGroup();
  }

  async getMarshalledKeyPackage() {
    // key packages are not meant to be re-used
    // so every time the client asks for a key package we create a new one
    await this.#resetJoinKeyPackage();

    return serializeKeyPackage(this.joinKeyPackage!);
  }

  async processProposals(proposals: Buffer) {
    if (!this.pendingGroupState)
      return console.warn('Cannot process proposals without any pending or established MLS group state');

    // if (!pendingGroupState_ && !currentState_) {
    //     DISCORD_LOG(LS_ERROR)
    //       << "Cannot process proposals without any pending or established MLS group state";
    //     return std::nullopt;
    // }

    const state = this.pendingGroupState;

    // if (!stateWithProposals_) {
    //     stateWithProposals_ = std::make_unique<::mlspp::State>(
    //       pendingGroupState_ ? *pendingGroupState_ : *currentState_);
    // }

    console.log(`Processing MLS proposals message of ${proposals.length} bytes`);
    // DISCORD_LOG(LS_INFO) << "Proposals: " << ::mlspp::bytes_ns::bytes(proposals);

    const opType: ProposalsOperationType = proposals.readUInt8(0);

    if (opType !== ProposalsOperationType.APPEND && opType !== ProposalsOperationType.REVOKE) {
      throw new Error(`Invalid ProposalsOperationType: ${opType}`);
    }

    if (opType === ProposalsOperationType.APPEND) {
      const { offset, v } = readVarint(proposals, 1);
      // TODO parse multiple messages
      const cursor = new DataCursor(v, proposals.subarray(offset + 1));
      await state.parseMLSMessageProposal(cursor);
      console.log({ cursor });
      
      // // success will queue the proposal, failure will throw
      // stateWithProposals_->handle(validatedMessage);

      // auto ref = suite.ref(validatedMessage.authenticated_content());

      // proposalQueue_.push_back({
      //   std::move(validatedMessage),
      //   std::move(ref),
      // });
    }

    // // generate a commit
    // auto commitSecret = ::mlspp::hpke::random_bytes(suite.secret_size());

    // auto commitOpts = ::mlspp::CommitOpts{
    //   {},    // no extra proposals
    //   true,  // inline tree in welcome
    //   false, // do not force path
    //   {}     // default leaf node options
    // };

    // auto [commitMessage, welcomeMessage, newState] =
    //   stateWithProposals_->commit(commitSecret, commitOpts, {});

    // DISCORD_LOG(LS_INFO)
    //   << "Prepared commit/welcome/next state for MLS group from received proposals";

    // // combine the commit and welcome messages into a single buffer
    // auto outStream = ::mlspp::tls::ostream();
    // outStream << commitMessage;

    // // keep a copy of the commit, we can check incoming pending group commit later for a match
    // pendingGroupCommit_ = std::make_unique<::mlspp::MLSMessage>(std::move(commitMessage));

    // // if there were any add proposals in this commit, then we also include the welcome message
    // if (welcomeMessage.secrets.size() > 0) {
    //     outStream << welcomeMessage;
    // }

    // // cache the outbound state in case we're the winning sender
    // outboundCachedGroupState_ = std::make_unique<::mlspp::State>(std::move(newState));

    // DISCORD_LOG(LS_INFO) << "Output: " << ::mlspp::bytes_ns::bytes(outStream.bytes());

    // return outStream.bytes();
  }

  #groupIdEmpty() {
    return this.groupId.every((v) => v === 0);
  }

  async #createLeafNode(transientKey?: KeyPair) {
    if (!transientKey) transientKey = this.ciphersuite.generateSigningKeyPair();

    this.signingKeys = transientKey;
    this.hpkeKeys = this.ciphersuite.generateKeyPair();

    this.leafnode = {
      encryption_key: this.hpkeKeys.publicKey,
      signature_key: this.signingKeys.publicKey,
      credential: {
        credential_type: CredentialType.BASIC,
        identity: this.credentialIdentity
      },
      capabilities: {
        versions: [ProtocolVersion.MLS10],
        cipher_suites: [this.ciphersuite.type],
        extensions: [],
        proposals: [],
        credentials: [CredentialType.BASIC]
      },
      leaf_node_source: LeafNodeSource.KEY_PACKAGE,
      lifetime: {
        not_before: 0n,
        not_after: 0xFFFFFFFFFFFFFFFFn
      },
      extensions: [],
      private_key: this.signingKeys.privateKey
    }
    this.leafnode.signature = await signLeafNode(this.leafnode, this.ciphersuite);
    // this.leafnode = await serializeLeafNode(this.ciphersuite, this.hpkePub, this.signingPub, this.userId, this.signingKeys.privateKey);

    console.log('Created MLS leaf node');
  }

  // TODO #createPendingGroup
  async #createPendingGroup() {
    if (this.#groupIdEmpty()) return console.warn('Cannot create MLS group without a group ID');
    if (!this.externalSender) return console.warn('Cannot create MLS group without ExternalSender');
    if (!this.leafnode) return console.warn('Cannot create MLS group without self leaf node');

    console.log('Creating a pending MLS group');

    // DISCORD_LOG(LS_INFO) << "Creating a pending MLS group";

    // auto ciphersuite = CiphersuiteForProtocolVersion(protocolVersion_);

    this.pendingGroupState = await MLSState.create(this);

    // pendingGroupState_ = std::make_unique<::mlspp::State>(
    //   groupId_,
    //   ciphersuite,
    //   *selfHPKEPrivateKey_,
    //   *selfSigPrivateKey_,
    //   *selfLeafNode_,
    //   GroupExtensionsForProtocolVersion(protocolVersion_, *externalSender_));

    // ::mlspp::ExtensionList GroupExtensionsForProtocolVersion(
    //   ProtocolVersion version,
    //   const ::mlspp::ExternalSender& externalSender) noexcept
    // {
    //     auto extensionList = ::mlspp::ExtensionList{};
    
    //     extensionList.add(::mlspp::ExternalSendersExtension{{
    //       {externalSender.signature_key, externalSender.credential},
    //     }});
    
    //     return extensionList;
    // }

    console.log('Created a pending MLS group');
    // DISCORD_LOG(LS_INFO) << "Created a pending MLS group";
  }

  async #resetJoinKeyPackage() {
    if (!this.leafnode) return console.warn('Cannot initialize join key package without a leaf node');
    // auto ciphersuite = CiphersuiteForProtocolVersion(protocolVersion_);

    this.joinInitKeys = this.ciphersuite.generateSigningKeyPair();

    // this.joinKeyPackage = await serializeKeyPackage(this.ciphersuite, initPub, this.leafnode, this.signingKeys!.privateKey);
    this.joinKeyPackage = {
      version: ProtocolVersion.MLS10,
      cipher_suite: this.ciphersuite.type,
      init_key: this.joinInitKeys.publicKey,
      leaf_node: this.leafnode,
      extensions: []
    }
    this.joinKeyPackage!.signature = await signKeyPackage(this.joinKeyPackage!, this.ciphersuite);

    console.log('Generated key package');
  }
}