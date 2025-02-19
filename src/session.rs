use napi::{bindgen_prelude::Buffer, Error};
use openmls::{group::*, prelude::{tls_codec::Serialize, *}};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

type DAVEProtocolVersion = u16;

/// Gets the [`Ciphersuite`] for a [`DAVEProtocolVersion`].
pub fn dave_protocol_version_to_ciphersuite(protocol_version: DAVEProtocolVersion) -> Result<Ciphersuite, Error> {
  match protocol_version {
    1 => Ok(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
    _ => Err(Error::from_reason("Unsupported protocol version".to_owned())),
  }
}

/// Gets the [`Capabilities`] for a [`DAVEProtocolVersion`].
pub fn dave_protocol_version_to_capabilities(protocol_version: DAVEProtocolVersion) -> Result<Capabilities, Error> {
  match protocol_version {
    1 => Ok(Capabilities::builder()
      .versions(vec![ProtocolVersion::Mls10])
      .ciphersuites(vec![dave_protocol_version_to_ciphersuite(protocol_version)?])
      .extensions(vec![])
      .proposals(vec![])
      .credentials(vec![CredentialType::Basic])
      .build()),
    _ => Err(Error::from_reason("Unsupported protocol version".to_owned())),
  }
}

#[napi]
#[derive(Debug,PartialEq)]
pub enum ProposalsOperationType {
  APPEND = 0,
  REVOKE = 1
}


#[napi(object)]
pub struct ProposalsResult {
	pub commit: Buffer,
	pub welcome: Option<Buffer>,
}

#[napi(js_name = "DAVESession")]
pub struct DaveSession {
  protocol_version: DAVEProtocolVersion,
  provider: OpenMlsRustCrypto,
  ciphersuite: Ciphersuite,
  group_id: GroupId,
  signer: SignatureKeyPair,
  credential_with_key: CredentialWithKey,

  external_sender: Option<ExternalSender>,
  pending_group: Option<MlsGroup>
}
 
#[napi]
impl DaveSession {
  #[napi(constructor)]
  pub fn new(protocol_version: u16, user_id: String, channel_id: String) -> napi::Result<Self> {
    let ciphersuite = dave_protocol_version_to_ciphersuite(protocol_version)?;
    let credential = BasicCredential::new(user_id.parse::<u64>()
      .map_err(|_| Error::from_reason("Invalid user id".to_owned()))?.to_be_bytes().into());
    let group_id = GroupId::from_slice(&channel_id.parse::<u64>()
      .map_err(|_| Error::from_reason("Invalid channel id".to_owned()))?.to_be_bytes());
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
      .map_err(|err| Error::from_reason(format!("Error generating a signature key pair: {err}")))?;
    let credential_with_key = CredentialWithKey {
      credential: credential.into(),
      signature_key: signer.public().into(),
    };

    Ok(DaveSession {
      protocol_version,
      ciphersuite,
      provider: OpenMlsRustCrypto::default(),
      group_id,
      signer,
      credential_with_key,
      external_sender: None,
      pending_group: None
    })
  }

  /// The DAVE protocol version used for this session.
  #[napi(getter)]
  pub fn protocol_version(&self) -> napi::Result<i32> {
    Ok(self.protocol_version as i32)
  }

  /// The user ID for this session.
  #[napi(getter)]
  pub fn user_id(&self) -> napi::Result<String> {
    Ok(
      u64::from_be_bytes(
        self.credential_with_key.credential.serialized_content().try_into()
          .map_err(|err| Error::from_reason(format!("Failed to convert user id: {err}")))?
      ).to_string()
    )
  }

  /// The channel ID (group ID in MLS standards) for this session.
  #[napi(getter)]
  pub fn channel_id(&self) -> napi::Result<String> {
    Ok(
      u64::from_be_bytes(
        self.group_id.as_slice().try_into()
        .map_err(|err| Error::from_reason(format!("Failed to convert channel id: {err}")))?
      ).to_string()
    )
  }

  /// The ciphersuite being used in this session.
  #[napi(getter)]
  pub fn ciphersuite(&self) -> napi::Result<i32> {
    Ok(self.ciphersuite as i32)
  }

  /// Set the external sender this session will recieve from.
  /// @param externalSenderData The serialized external sender data.
  /// @throws Will throw if the external sender is invalid.
  /// @see https://daveprotocol.com/#dave_mls_external_sender_package-25
  #[napi]
  pub fn set_external_sender(&mut self, external_sender_data: Buffer) -> napi::Result<()> {
    let external_sender = ExternalSender::tls_deserialize_exact_bytes(&external_sender_data)
      .map_err(|err| Error::from_reason(format!("Failed to deserialize external sender: {err}")))?;
    self.external_sender = Some(external_sender);
    Ok(())
  }

  /// Create and return the serialized key package buffer.
  /// Key packages are not meant to be reused, and will be recreated on each call of this function.
  #[napi]
  pub fn get_serialized_key_package(&mut self) -> napi::Result<Buffer> {
    // Set lifetime to max time span: https://daveprotocol.com/#validation
    let lifetime = {
      let data: [u8; 0x10] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // not_before
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // not_after
      ];
      Lifetime::tls_deserialize_exact_bytes(&data)
        .map_err(|err| Error::from_reason(format!("Error deserializing lifetime: {err}")))?
    };

    // This key package is stored in the provider for later
    let key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(dave_protocol_version_to_capabilities(self.protocol_version).unwrap())
        .key_package_lifetime(lifetime)
        .build(self.ciphersuite, &self.provider, &self.signer, self.credential_with_key.clone())
        .map_err(|err| Error::from_reason(format!("Error creating key package: {err}")))?;

    let buffer = key_package.key_package().tls_serialize_detached()
      .map_err(|err| Error::from_reason(format!("Error serializing key package: {err}")))?;

    Ok(Buffer::from(buffer))
  }

  /// Create a pending group that may recieve proposals.
  /// You must use {@link getSerializedKeyPackage} and {@link setExternalSender} before using this function.
  #[napi]
  pub fn create_pending_group(&mut self) -> napi::Result<()> {
    if self.external_sender.is_none() {
      return Err(Error::from_reason("No external sender set".to_owned()));
    }
  
    let mls_group_create_config = MlsGroupCreateConfig::builder()
      .with_group_context_extensions(Extensions::single(Extension::ExternalSenders(vec![self.external_sender.clone().unwrap()])))
      .map_err(|err| Error::from_reason(format!("Error adding external sender to group: {err}")))?
      .ciphersuite(self.ciphersuite)
      .capabilities(dave_protocol_version_to_capabilities(self.protocol_version).unwrap())
      .use_ratchet_tree_extension(true)
      .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
      .build();

    let group = MlsGroup::new_with_group_id(
        &self.provider,
        &self.signer,
        &mls_group_create_config,
        self.group_id.clone(),
        self.credential_with_key.clone(),
      )
      .map_err(|err| Error::from_reason(format!("Error creating a group: {err}")))?;

    // group.delete(self.provider.storage());
    self.pending_group = Some(group);

    Ok(())
  }

  /// Process proposals from an opcode 27 payload.
  /// @param operationType The operation type of the proposals.
  /// @param proposals The vector of proposals or proposal refs of the payload. (depending on operation type)
  /// @see https://daveprotocol.com/#dave_mls_proposals-27
  #[napi]
  pub fn process_proposals(&mut self, operation_type: ProposalsOperationType, proposals: Buffer) -> napi::Result<ProposalsResult> {
    // TODO account for current group too
    // TODO support revokes
    if self.pending_group.is_none() {
      return Err(Error::from_reason("Cannot process proposals without a group".to_owned()));
    }

    let group = self.pending_group.as_mut().unwrap();

    println!("processing proposals, optype {:?}", operation_type);

    let proposals: Vec<u8> = VLBytes::tls_deserialize_exact_bytes(&proposals)
      .map_err(|err| Error::from_reason(format!("Error deserializing proposal vector: {err}")))?
      .into();

    if operation_type == ProposalsOperationType::APPEND {
      let mut remaining_bytes: &[u8] = &proposals;
      while remaining_bytes.len() != 0 {
        let (mls_message, leftover) =
          MlsMessageIn::tls_deserialize_bytes(&remaining_bytes)
          .map_err(|err| Error::from_reason(format!("Error deserializing MLS message: {err}")))?;
        remaining_bytes = leftover;
  
        let protocol_message = mls_message
          .try_into_protocol_message()
          .map_err(|_| Error::from_reason("MLSMessage did not have a PublicMessage".to_owned()))?;

        let processed_message = group
          .process_message(&self.provider, protocol_message)
          .map_err(|err| Error::from_reason(format!("Could not process message: {err}")))?;

        
        match processed_message.into_content() {
          ProcessedMessageContent::ProposalMessage(proposal) => {
            group
              .store_pending_proposal(self.provider.storage(), *proposal)
              .map_err(|err| Error::from_reason(format!("Could not store proposal: {err}")))?;
          }
          _ => return Err(Error::from_reason("ProcessedMessage is not a ProposalMessage".to_owned())),
        }
      }
    } else {
      return Err(Error::from_reason("Revoked proposals not supported yet".to_owned()))
    }

    let prev_member_count = group.members().count();
    let (commit, welcome, _group_info) = group
      .commit_to_pending_proposals(&self.provider, &self.signer)
      .map_err(|err| Error::from_reason(format!("Error committing pending proposals: {err}")))?;
    group
      .merge_pending_commit(&self.provider)
      .map_err(|err| Error::from_reason(format!("Error merging pending proposals: {err}")))?;

    let mut welcome_buffer: Option<Buffer> = None;

    if group.members().count() > prev_member_count {
      // let welcome = welcome.expect("Welcome was not returned").into_welcome().expect("Expected message to be a welcome message");
      match welcome {
        Some(mls_message_out) => {
          match mls_message_out.into_welcome() {
            Some(welcome) => {
              welcome_buffer = Some(
                Buffer::from(
                  welcome.tls_serialize_detached()
                    .map_err(|err| Error::from_reason(format!("Error serializing welcome: {err}")))?
                )
              )
            },
            _ => return Err(Error::from_reason("MLSMessage was not a Welcome".to_owned())),
          }
        },
        _ => return Err(Error::from_reason("Welcome was not returned when there are new members".to_owned())),
      }
    }

    let commit_buffer = commit.tls_serialize_detached()
      .map_err(|err| Error::from_reason(format!("Error serializing commit: {err}")))?;

    Ok(ProposalsResult {
      commit: Buffer::from(commit_buffer),
      welcome: welcome_buffer
    })
  }

  #[napi(getter)]
  pub fn items_in_storage(&self) -> napi::Result<i32> {
    let map_read_guard = self.provider.storage().values.read()
      .map_err(|err| Error::from_reason(format!("MemoryStorage error: {err}")))?;
    Ok(map_read_guard.len() as i32)
  }

  /// @ignore
  #[napi]
  pub fn to_string(&self) -> napi::Result<String> {
    Ok(format!("DAVESession {{ protocolVersion: {}, userId: {}, channelId: {} }}", self.protocol_version()?, self.user_id()?, self.channel_id()?))
  }
}