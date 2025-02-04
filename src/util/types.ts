import { ProtocolVersion, ExtensionType, ProposalType, CredentialType, CipherSuite, LeafNodeSource } from "./constants";

export interface Capabilities {
  versions: ProtocolVersion[];
  cipher_suites: CipherSuite[];
  extensions: ExtensionType[];
  proposals: ProposalType[];
  credentials: CredentialType[];
}

export interface Certificate {
  cert_data: Uint8Array;
}

export interface CredentialBasic {
  credential_type: CredentialType.BASIC;
  identity: Uint8Array;
}

export interface CredentialX509 {
  credential_type: CredentialType.X509;
  credentials: Certificate[];
}

export type Credential = CredentialBasic | CredentialX509;

export interface Lifetime {
  not_before: bigint;
  not_after: bigint;
}

export type ExtensionData<T extends ExtensionType> = T extends ExtensionType.REQUIRED_CAPABILITIES ? RequiredCapabilities : (Uint8Array | undefined);

export interface Extension<T extends ExtensionType> {
  extension_type: T;
  extension_data: ExtensionData<T>;
}

export interface RequiredCapabilities {
  extension_types: ExtensionType[];
  proposal_types: ProposalType[];
  credential_types: CredentialType[];
}

export interface TreeNodeBase {
  encryption_key: Uint8Array;
  private_key?: Uint8Array;
}

export interface ParentNode extends TreeNodeBase {
  parent_hash: Uint8Array;
  unmerged_leaves: Array<number>;
}

export interface LeafNodeBase extends TreeNodeBase {
  signature_key: Uint8Array;
  credential: Credential;
  capabilities: Capabilities;
  leaf_node_source: LeafNodeSource;
  extensions: Extension<ExtensionType.APPLICATION_ID>[];
  signature?: Uint8Array;
}

export interface LeafNodeKeyPackage extends LeafNodeBase {
  leaf_node_source: LeafNodeSource.KEY_PACKAGE;
  lifetime: Lifetime;
}

export interface LeafNodeCommit extends LeafNodeBase {
  leaf_node_source: LeafNodeSource.COMMIT;
  parent_hash: Uint8Array;
}

export type LeafNode = LeafNodeBase | LeafNodeKeyPackage | LeafNodeCommit;

export type RatchetTreeNode = ParentNode | LeafNode;

export interface KeyPackage {
  version: ProtocolVersion;
  cipher_suite: CipherSuite;
  init_key: Uint8Array;
  leaf_node: LeafNodeKeyPackage;
  extensions: Extension<ExtensionType>[];
  signature?: Uint8Array;
}

export interface GroupContext {
  version: ProtocolVersion.MLS10;
  cipher_suite: CipherSuite;
  group_id: Uint8Array;
  epoch: bigint;
  tree_hash: Uint8Array;
  confirmed_transcript_hash: Uint8Array;
  extensions: Extension<ExtensionType.REQUIRED_CAPABILITIES | ExtensionType.EXTERNAL_SENDERS>[];
}

export interface HPKECipherText {
  kem_output: Uint8Array;
  ciphertext: Uint8Array;
}

export interface UpdatePathNode {
  encryption_key: Uint8Array;
  encrypted_path_secret: HPKECipherText;
}

export interface UpdatePath {
  leaf_node: LeafNode;
  nodes: UpdatePathNode[];
}