export const DAVE_PROTOCOL_VERSION = 1;

/**
 * Cipher suite type supported by MLS. (uint16)
 * @see https://www.iana.org/assignments/mls/mls.xhtml#mls-ciphersuites
 */
export enum CipherSuite {
  MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 1,
  MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 2,
  MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 3,
  MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 4,
  MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 5,
  MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 6,
  MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 7
};

/** 
 * Extension type for users. (uint16)
 * @see https://www.iana.org/assignments/mls/mls.xhtml#mls-extension-types
 */
export enum ExtensionType {
  APPLICATION_ID = 1,
  RATCHET_TREE = 2,
  REQUIRED_CAPABILITIES = 3,
  EXTERNAL_PUB = 4,
  EXTERNAL_SENDERS = 5,
};

/**
 * The credential type. (uint16)
 * @see https://www.iana.org/assignments/mls/mls.xhtml#mls-credential-types
 */
export enum CredentialType {
  BASIC = 1,
  X509 = 2,
};

/**
 * The protocol version of an MLS message. (uint16)
 * @see https://www.rfc-editor.org/rfc/rfc9420.html#section-6
 */
export enum ProtocolVersion {
  MLS10 = 1,
};

/**
 * The source of a leaf node. (uint8)
 * @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2
 */
export enum LeafNodeSource {
  KEY_PACKAGE = 1,
  UPDATE = 2,
  COMMIT = 3,
};

/**
 * The proposal type for MLS messages. (uint16)
 * @see https://www.iana.org/assignments/mls/mls.xhtml#mls-proposal-types
 */
export enum ProposalType {
  ADD = 1,
  UPDATE = 2,
  REMOVE = 3,
  PSK = 4,
  REINIT = 5,
  EXTERNAL_INIT = 6,
  GROUP_CONTEXT_EXTENSIONS = 7,
};

/**
 * The proposal operation type for DAVE. (uint8)
 * @see https://daveprotocol.com/#dave_mls_proposals-27
 */
export enum ProposalsOperationType {
  APPEND = 0,
  REVOKE = 1,
};

/**
 * The type of pre-shared key. (uint8)
 * @see https://www.rfc-editor.org/rfc/rfc9420.html#section-8.4
 */
export enum PSKType {
  EXTERNAL = 1,
  RESUMPTION = 2,
};

/**
 * The resumption usage of a pre-shared key. (uint8)
 * @see https://www.rfc-editor.org/rfc/rfc9420.html#section-8.4
 */
export enum ResumptionPSKUsage {
  APPLICATION = 1,
  REINIT = 2,
  BRANCH = 3,
};

/**
 * The wire format of an MLS message. (uint16)
 * @see https://www.iana.org/assignments/mls/mls.xhtml#mls-wire-formats
 */
export enum WireFormat {
  MLS_PUBLIC_MESSAGE = 1,
  MLS_PRIVATE_MESSAGE = 2,
  MLS_WELCOME = 3,
  MLS_GROUP_INFO = 4,
  MLS_KEY_PACKAGE = 5,
};

/**
 * The content type for framed content. (uint8)
 * @see https://www.rfc-editor.org/rfc/rfc9420.html#section-6-4
 */
export enum ContentType {
  APPLICATION = 1,
  PROPOSAL = 2,
  COMMIT = 3,
};

/**
 * The type of sender of framed content. (uint8)
 * @see https://www.rfc-editor.org/rfc/rfc9420.html#section-6-4
 */
export enum SenderType {
  MEMBER = 1,
  EXTERNAL = 2,
  NEW_MEMBER_PROPOSAL = 3,
  NEW_MEMBER_COMMIT = 4,
};

/**
 * The type of a ProposalOrRef, either a proposal or a reference. (uint8)
 * @see https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4
 */
export enum ProposalOrRefType {
  PROPOSAL = 1,
  REFERENCE = 2,
};

/**
 * The type of node. (uint8)
 * @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8-5
 */
export enum NodeType {
  LEAF = 1,
  PARENT = 2,
};

export const LABEL_HEADER = 'MLS 1.0 ';

export enum MLSReferenceLabels {
  KEY_PACKAGE_REFERENCE = LABEL_HEADER + 'KeyPackage Reference',
  PROPOSAL_REFERENCE = LABEL_HEADER + 'Proposal Reference',
}

export enum MLSLabels {
  // MLS Signature Labels
  // https://www.rfc-editor.org/rfc/rfc9420.html#section-17.6
  FRAMED_CONTENT_TBS = 'FramedContentTBS',
  LEAF_NODE_TBS = 'LeafNodeTBS',
  KEY_PACKAGE_TBS = 'KeyPackageTBS',
  GROUP_INFO_TBS = 'GroupInfoTBS',

  // MLS Public Key Encryption Labels
  // https://www.rfc-editor.org/rfc/rfc9420.html#section-17.7
  UPDATE_PATH_NODE = 'UpdatePathNode',
  WELCOME = 'Welcome',
}