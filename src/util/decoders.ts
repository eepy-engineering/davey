import { DataCursor } from ".";
import { CipherSuite, ContentType, CredentialType, ExtensionType, LeafNodeSource, ProposalType, ProtocolVersion, SenderType, WireFormat } from "./constants";
import { AddProposal, Capabilities, Certificate, Credential, CredentialBasic, CredentialX509, Extension, KeyPackage, LeafNode, Lifetime, RemoveProposal, Sender, SenderExternal, SenderMember } from "./types";

export function decodeCredential(cursor: DataCursor): Credential {
  const credentialType: CredentialType = cursor.readU16();
  if (credentialType === CredentialType.BASIC) {
    return {
      credential_type: credentialType,
      identity: cursor.readVector()
    } satisfies CredentialBasic;
  } else if (credentialType === CredentialType.X509) {
    const credentials = cursor.parseVector((c) => 
      ({ cert_data: c.readVector() } satisfies Certificate)
    );
    return {
      credential_type: credentialType,
      credentials: credentials
    } satisfies CredentialX509;
  } else throw new Error(`Invalid credential type (${credentialType})`);
}

export function decodeCapabilities(cursor: DataCursor): Capabilities {
  const versions = cursor.parseVector<ProtocolVersion>((c) => c.readU16());
  const cipher_suites = cursor.parseVector<CipherSuite>((c) => c.readU16());
  const extensions = cursor.parseVector<ExtensionType>((c) => c.readU16());
  const proposals = cursor.parseVector<ProposalType>((c) => c.readU16());
  const credentials = cursor.parseVector<CredentialType>((c) => c.readU16());
  const capabilities = {
    versions,
    cipher_suites,
    extensions,
    proposals,
    credentials
  } satisfies Capabilities;
  return capabilities;
}

export function decodeLifetime(cursor: DataCursor): Lifetime {
  const not_before = cursor.readU64();
  const not_after = cursor.readU64();
  const lifetime = {
    not_before,
    not_after
  };
  return lifetime;
}

export function decodeExtension(cursor: DataCursor): Extension<ExtensionType> {
  const extension_type: ExtensionType = cursor.readU16();
  const extension_data = cursor.readVector();
  if (extension_type === ExtensionType.REQUIRED_CAPABILITIES) {
    const extDataCursor = new DataCursor(extension_data.byteLength, extension_data);
    const extension_types = extDataCursor.parseVector<ExtensionType>((c) => c.readU16());
    const proposal_types = extDataCursor.parseVector<ProposalType>((c) => c.readU16());
    const credential_types = extDataCursor.parseVector<CredentialType>((c) => c.readU16());
    const extension = {
      extension_type,
      extension_data: {
        extension_types,
        proposal_types,
        credential_types
      }
    } satisfies Extension<ExtensionType.REQUIRED_CAPABILITIES>;
    return extension;
  }

  return {
    extension_type,
    extension_data
  };
}

export function decodeLeafNode(cursor: DataCursor): LeafNode {
  const encryption_key = cursor.readVector();
  const signature_key = cursor.readVector();
  const credential = decodeCredential(cursor);
  const capabilities = decodeCapabilities(cursor);
  const leaf_node_source: LeafNodeSource = cursor.readU8();
  let lifetime: Lifetime | undefined = undefined;
  let parent_hash: Uint8Array | undefined = undefined;
  if (leaf_node_source === LeafNodeSource.KEY_PACKAGE)
    lifetime = decodeLifetime(cursor);
  if (leaf_node_source === LeafNodeSource.COMMIT)
    parent_hash = cursor.readVector();
  const extensions = cursor.parseVector((c) => decodeExtension(c));
  const signature = cursor.readVector();
  const leaf_node = {
    encryption_key,
    signature_key,
    credential,
    capabilities,
    leaf_node_source,
    lifetime,
    parent_hash,
    extensions,
    signature
  } as any;
  return leaf_node;
}

export function decodeKeyPackage(cursor: DataCursor): KeyPackage {
    const version: ProtocolVersion = cursor.readU16();
    const cipher_suite: CipherSuite = cursor.readU16();
    const init_key = cursor.readVector();
    const leaf_node = decodeLeafNode(cursor);
    const extensions = cursor.parseVector((c) => decodeExtension(c));
    const signature = cursor.readVector();
    const keyPackage = {
        version,
        cipher_suite,
        init_key,
        leaf_node,
        extensions,
        signature
    } as any;
    return keyPackage;
}

export function decodeSender(cursor: DataCursor): Sender {
  const senderType: SenderType = cursor.readU8();

  if (senderType !== SenderType.MEMBER && senderType !== SenderType.EXTERNAL && senderType !== SenderType.NEW_MEMBER_PROPOSAL && senderType !== SenderType.NEW_MEMBER_COMMIT)
    throw new Error(`Invalid sender type (${senderType})`);

  if (senderType === SenderType.MEMBER)
    return {
      sender_type: senderType,
      leaf_index: cursor.readU32()
    } satisfies SenderMember;

  if (senderType === SenderType.EXTERNAL)
    return {
      sender_type: senderType,
      sender_index: cursor.readU32()
    } satisfies SenderExternal;

  return { sender_type: senderType } satisfies Sender;
}

export function decodeProposal(cursor: DataCursor): AddProposal | RemoveProposal {
  const proposal_type: ProposalType = cursor.readU16();

  if (proposal_type === ProposalType.ADD) {
    const key_package = decodeKeyPackage(cursor);
    return {
      proposal_type,
      key_package
    } satisfies AddProposal;
  } else if (proposal_type === ProposalType.REMOVE) {
    return {
      proposal_type,
      removed: cursor.readU32()
    } satisfies RemoveProposal;
  } else throw new Error(`Invalid proposal type (${proposal_type})`);
}

export function decodeFramedContent(cursor: DataCursor) {
  const group_id = cursor.readVector();
  const epoch = cursor.readU64();
  const sender = decodeSender(cursor);
  const authenticated_data = cursor.readVector();

  const content_type: ContentType = cursor.readU8();

  const base = {
    group_id,
    epoch,
    sender,
    authenticated_data,
    content_type
  };

  if (content_type === ContentType.PROPOSAL) {
    const proposal = decodeProposal(cursor);
    return { ...base, proposal };
  } else throw new Error(`Invalid content type (${content_type})`);
}

export function decodeFramedContentAuthData(cursor: DataCursor, contentType: ContentType) {
  const signature = cursor.readVector();

  if (contentType === ContentType.COMMIT) {
    const confirmation_tag = cursor.readVector();
    return { signature, confirmation_tag };
  } else return { signature };
}

export function decodePublicMessage(cursor: DataCursor) {
  const content = decodeFramedContent(cursor);
  const auth = decodeFramedContentAuthData(cursor, content.content_type);

  const base = { content, auth };

  if (content.sender.sender_type === SenderType.MEMBER) {
    const membership_tag = cursor.readVector();
    return { ...base, membership_tag };
  } else return base;
}

export function decodeMLSMessage(cursor: DataCursor) {
  const protocol_version: ProtocolVersion = cursor.readU16();
  const wire_format: WireFormat = cursor.readU16();

  if (wire_format === WireFormat.MLS_PUBLIC_MESSAGE) {
    const public_message = decodePublicMessage(cursor);
    return { protocol_version, wire_format, public_message };
  } else throw new Error(`Invalid wire format (${wire_format})`);
}