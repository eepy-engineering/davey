use log::{debug, trace, warn};
use napi::{
  bindgen_prelude::{AsyncTask, Buffer},
  Error,
};
use openmls::{
  group::*,
  prelude::{hash_ref::ProposalRef, tls_codec::Serialize, *},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use std::collections::HashMap;

use crate::{
  cryptor::{
    decryptor::{DecryptionStats, Decryptor},
    encryptor::{EncryptionStats, Encryptor},
    hash_ratchet::HashRatchet,
    Codec, MediaType, AES_GCM_128_KEY_BYTES, OPUS_SILENCE_PACKET,
  },
  generate_displayable_code_internal, AsyncPairwiseFingerprintSession,
  AsyncSessionVerificationCode, DAVEProtocolVersion, SigningKeyPair,
};

const USER_MEDIA_KEY_BASE_LABEL: &str = "Discord Secure Frames v0";

/// Gets the [`Ciphersuite`] for a [`DAVEProtocolVersion`].
pub fn dave_protocol_version_to_ciphersuite(
  protocol_version: DAVEProtocolVersion,
) -> Result<Ciphersuite, Error> {
  match protocol_version {
    1 => Ok(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
    _ => Err(napi_invalid_arg_error!("Unsupported protocol version")),
  }
}

/// Gets the [`Capabilities`] for a [`DAVEProtocolVersion`].
pub fn dave_protocol_version_to_capabilities(
  protocol_version: DAVEProtocolVersion,
) -> Result<Capabilities, Error> {
  match protocol_version {
    1 => Ok(
      Capabilities::builder()
        .versions(vec![ProtocolVersion::Mls10])
        .ciphersuites(vec![dave_protocol_version_to_ciphersuite(
          protocol_version,
        )?])
        .extensions(vec![])
        .proposals(vec![])
        .credentials(vec![CredentialType::Basic])
        .build(),
    ),
    _ => Err(napi_invalid_arg_error!("Unsupported protocol version")),
  }
}

/// Generate a key fingerprint.
fn generate_key_fingerprint(version: u16, user_id: u64, key: Vec<u8>) -> Vec<u8> {
  let mut result: Vec<u8> = vec![];
  result.extend(version.to_be_bytes());
  result.extend(key);
  result.extend(user_id.to_be_bytes());
  result
}

/// The maximum supported version of the DAVE protocol.
#[napi]
pub const DAVE_PROTOCOL_VERSION: u16 = 1;

#[napi]
#[derive(Debug, PartialEq)]
pub enum ProposalsOperationType {
  APPEND = 0,
  REVOKE = 1,
}

#[napi]
#[derive(Debug, PartialEq, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum SessionStatus {
  INACTIVE = 0,
  PENDING = 1,
  AWAITING_RESPONSE = 2,
  ACTIVE = 3,
}

#[napi(object)]
pub struct ProposalsResult {
  pub commit: Option<Buffer>,
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
  group: Option<MlsGroup>,
  status: SessionStatus,
  ready: bool,

  privacy_code: String,
  encryptor: Encryptor,
  decryptors: HashMap<u64, Decryptor>,
}

#[napi]
impl DaveSession {
  /// @param protocolVersion The protocol version to use.
  /// @param userId The user ID of the session.
  /// @param channelId The channel ID of the session.
  /// @param keyPair The key pair to use for this session. Will generate a new one if not specified.
  #[napi(constructor)]
  pub fn new(
    protocol_version: u16,
    user_id: String,
    channel_id: String,
    key_pair: Option<SigningKeyPair>,
  ) -> napi::Result<Self> {
    let ciphersuite = dave_protocol_version_to_ciphersuite(protocol_version)?;
    let credential = BasicCredential::new(
      user_id
        .parse::<u64>()
        .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?
        .to_be_bytes()
        .into(),
    );
    let group_id = GroupId::from_slice(
      &channel_id
        .parse::<u64>()
        .map_err(|_| napi_invalid_arg_error!("Invalid channel id"))?
        .to_be_bytes(),
    );
    let signer = if let Some(key_pair) = key_pair {
      SignatureKeyPair::from_raw(
        ciphersuite.signature_algorithm(),
        key_pair.private.into(),
        key_pair.public.into(),
      )
    } else {
      SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .map_err(|err| napi_error!("Error generating a signature key pair: {err}"))?
    };
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
      group: None,
      status: SessionStatus::INACTIVE,
      ready: false,
      privacy_code: String::new(),
      encryptor: Encryptor::new(),
      decryptors: HashMap::new(),
    })
  }

  /// Resets and re-initializes the session.
  /// @param protocolVersion The protocol version to use.
  /// @param userId The user ID of the session.
  /// @param channelId The channel ID of the session.
  /// @param keyPair The key pair to use for this session. Will generate a new one if not specified.
  #[napi]
  pub fn reinit(
    &mut self,
    protocol_version: u16,
    user_id: String,
    channel_id: String,
    key_pair: Option<SigningKeyPair>,
  ) -> napi::Result<()> {
    self.reset()?;

    let ciphersuite = dave_protocol_version_to_ciphersuite(protocol_version)?;
    let credential = BasicCredential::new(
      user_id
        .parse::<u64>()
        .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?
        .to_be_bytes()
        .into(),
    );
    let group_id = GroupId::from_slice(
      &channel_id
        .parse::<u64>()
        .map_err(|_| napi_invalid_arg_error!("Invalid channel id"))?
        .to_be_bytes(),
    );
    let signer = if let Some(key_pair) = key_pair {
      SignatureKeyPair::from_raw(
        ciphersuite.signature_algorithm(),
        key_pair.private.into(),
        key_pair.public.into(),
      )
    } else {
      SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .map_err(|err| napi_error!("Error generating a signature key pair: {err}"))?
    };
    let credential_with_key = CredentialWithKey {
      credential: credential.into(),
      signature_key: signer.public().into(),
    };

    self.protocol_version = protocol_version;
    self.ciphersuite = ciphersuite;
    self.group_id = group_id;
    self.signer = signer;
    self.credential_with_key = credential_with_key;
    self.privacy_code.clear();
    self.encryptor = Encryptor::new();
    self.decryptors.clear();

    if self.external_sender.is_some() {
      self.create_pending_group()?;
    }

    Ok(())
  }

  /// Resets the session by deleting the group and clearing the storage.
  /// If you want to re-initialize the session, use {@link reinit}.
  #[napi]
  pub fn reset(&mut self) -> napi::Result<()> {
    debug!("Resetting MLS session");

    // Delete group
    if self.group.is_some() {
      self
        .group
        .take()
        .unwrap()
        .delete(self.provider.storage())
        .map_err(|err| napi_error!("Error clearing group: {err}"))?;
    }

    // Clear storage
    self
      .provider
      .storage()
      .values
      .write()
      .map_err(|err| napi_error!("MemoryStorage error: {err}"))?
      .clear();

    self.status = SessionStatus::INACTIVE;
    self.ready = false;

    Ok(())
  }

  /// The DAVE protocol version used for this session.
  #[napi(getter)]
  pub fn protocol_version(&self) -> napi::Result<i32> {
    Ok(self.protocol_version as i32)
  }

  /// The user ID for this session.
  #[napi(getter)]
  pub fn user_id(&self) -> napi::Result<String> {
    Ok(self.user_id_as_u64()?.to_string())
  }

  fn user_id_as_u64(&self) -> napi::Result<u64> {
    Ok(u64::from_be_bytes(
      self
        .credential_with_key
        .credential
        .serialized_content()
        .try_into()
        .map_err(|err| napi_error!("Failed to convert our user id: {err}"))?,
    ))
  }

  /// The channel ID (group ID in MLS standards) for this session.
  #[napi(getter)]
  pub fn channel_id(&self) -> napi::Result<String> {
    Ok(
      u64::from_be_bytes(
        self
          .group_id
          .as_slice()
          .try_into()
          .map_err(|err| napi_error!("Failed to convert channel id: {err}"))?,
      )
      .to_string(),
    )
  }

  /// The ciphersuite being used in this session.
  #[napi(getter)]
  pub fn ciphersuite(&self) -> napi::Result<i32> {
    Ok(self.ciphersuite as i32)
  }

  /// The status of this session.
  #[napi(getter)]
  pub fn status(&self) -> napi::Result<SessionStatus> {
    Ok(self.status)
  }

  /// Whether this session has an established group and is ready to encrypt/decrypt frames.
  #[napi(getter)]
  pub fn ready(&self) -> napi::Result<bool> {
    Ok(self.ready)
  }

  /// Get the epoch authenticator of this session's group.
  #[napi]
  pub fn get_epoch_authenticator(&self) -> napi::Result<Buffer> {
    if self.group.is_none() || self.status == SessionStatus::PENDING {
      return Err(napi_error!(
        "Cannot epoch authenticator without an established MLS group"
      ));
    }

    Ok(Buffer::from(
      self
        .group
        .as_ref()
        .unwrap()
        .epoch_authenticator()
        .as_slice(),
    ))
  }

  /// Get the voice privacy code of this session's group.
  /// The result of this is created and cached each time a new transition is executed.
  /// This is the equivalent of `generateDisplayableCode(epochAuthenticator, 30, 5)`.
  /// @returns The current voice privacy code, or an empty string if the session is not active.
  /// @see https://daveprotocol.com/#displayable-codes
  #[napi(getter)]
  pub fn voice_privacy_code(&self) -> napi::Result<&String> {
    Ok(&self.privacy_code)
  }

  /// Set the external sender this session will recieve from.
  /// @param externalSenderData The serialized external sender data.
  /// @throws Will throw if the external sender is invalid, or if the group has been established already.
  /// @see https://daveprotocol.com/#dave_mls_external_sender_package-25
  #[napi]
  pub fn set_external_sender(&mut self, external_sender_data: Buffer) -> napi::Result<()> {
    if self.status == SessionStatus::AWAITING_RESPONSE || self.status == SessionStatus::ACTIVE {
      return Err(napi_error!(
        "Cannot set an external sender after joining an established group"
      ));
    }

    // Delete group to avoid clashing
    if self.group.is_some() {
      self
        .group
        .take()
        .unwrap()
        .delete(self.provider.storage())
        .map_err(|err| napi_error!("Error clearing previous group: {err}"))?;
    }

    let external_sender = ExternalSender::tls_deserialize_exact_bytes(&external_sender_data)
      .map_err(|err| napi_error!("Failed to deserialize external sender: {err}"))?;

    self.external_sender = Some(external_sender);
    debug!("External sender set.");

    self.create_pending_group()?;

    Ok(())
  }

  /// Create, store, and return the serialized key package buffer.
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
        .map_err(|err| napi_error!("Error deserializing lifetime: {err}"))?
    };

    // This key package is stored in the provider for later
    let key_package = KeyPackage::builder()
      .key_package_extensions(Extensions::empty())
      .leaf_node_capabilities(dave_protocol_version_to_capabilities(self.protocol_version).unwrap())
      .key_package_lifetime(lifetime)
      .build(
        self.ciphersuite,
        &self.provider,
        &self.signer,
        self.credential_with_key.clone(),
      )
      .map_err(|err| napi_error!("Error creating key package: {err}"))?;

    let buffer = key_package
      .key_package()
      .tls_serialize_detached()
      .map_err(|err| napi_error!("Error serializing key package: {err}"))?;

    debug!(
      "Created key package for channel {:?}.",
      self.channel_id().ok().unwrap_or_default()
    );

    Ok(Buffer::from(buffer))
  }

  fn create_pending_group(&mut self) -> napi::Result<()> {
    if self.external_sender.is_none() {
      return Err(napi_error!("No external sender set"));
    }

    let mls_group_create_config = MlsGroupCreateConfig::builder()
      .with_group_context_extensions(Extensions::single(Extension::ExternalSenders(vec![self
        .external_sender
        .clone()
        .unwrap()])))
      .map_err(|err| napi_error!("Error adding external sender to group: {err}"))?
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
    .map_err(|err| napi_error!("Error creating a group: {err}"))?;

    self.group = Some(group);
    self.status = SessionStatus::PENDING;

    debug!(
      "Created pending group for channel {:?}.",
      self.channel_id().ok().unwrap_or_default()
    );

    Ok(())
  }

  /// Process proposals from an opcode 27 payload.
  /// @param operationType The operation type of the proposals.
  /// @param proposals The vector of proposals or proposal refs of the payload. (depending on operation type)
  /// @param recognizedUserIds The recognized set of user IDs gathered from the voice gateway. Recommended to set so that incoming users are checked against.
  /// @returns A commit (if there were queued proposals) and a welcome (if a member was added) that should be used to send an [opcode 28: dave_mls_commit_welcome](https://daveprotocol.com/#dave_mls_commit_welcome-28) ONLY if a commit was returned.
  /// @see https://daveprotocol.com/#dave_mls_proposals-27
  #[napi]
  pub fn process_proposals(
    &mut self,
    operation_type: ProposalsOperationType,
    proposals: Buffer,
    recognized_user_ids: Option<Vec<String>>,
  ) -> napi::Result<ProposalsResult> {
    if self.group.is_none() {
      return Err(napi_error!("Cannot process proposals without a group"));
    }

    let group = self.group.as_mut().unwrap();

    let recognized_user_ids = recognized_user_ids
      .map(|ids| {
        ids
          .into_iter()
          .map(|id| {
            id.parse::<u64>()
              .map_err(|_| napi_invalid_arg_error!("Invalid user id"))
          })
          .collect::<Result<Vec<u64>, Error>>()
      })
      .transpose()?;

    debug!("Processing proposals, optype {:?}", operation_type);

    let proposals: Vec<u8> = VLBytes::tls_deserialize_exact_bytes(&proposals)
      .map_err(|err| napi_error!("Error deserializing proposal vector: {err}"))?
      .into();
    let mut commit_adds_members = false;

    if operation_type == ProposalsOperationType::APPEND {
      let mut remaining_bytes: &[u8] = &proposals;
      while !remaining_bytes.is_empty() {
        let (mls_message, leftover) = MlsMessageIn::tls_deserialize_bytes(remaining_bytes)
          .map_err(|err| napi_error!("Error deserializing MLS message: {err}"))?;
        remaining_bytes = leftover;

        let protocol_message = mls_message
          .try_into_protocol_message()
          .map_err(|_| napi_error!("MLSMessage did not have a PublicMessage"))?;

        let processed_message = group
          .process_message(&self.provider, protocol_message)
          .map_err(|err| napi_error!("Could not process message: {err}"))?;

        match processed_message.into_content() {
          ProcessedMessageContent::ProposalMessage(proposal) => {
            if let Proposal::Add(add_proposal) = proposal.proposal() {
              let incoming_user_id = u64::from_be_bytes(
                add_proposal
                  .key_package()
                  .leaf_node()
                  .credential()
                  .serialized_content()
                  .try_into()
                  .map_err(|err| napi_error!("Failed to convert proposal user id: {err}"))?,
              );

              debug!(
                "Storing add proposal for user {:?}",
                incoming_user_id.to_string()
              );

              if let Some(ref ids) = recognized_user_ids {
                if !ids.contains(&incoming_user_id) {
                  return Err(napi_error!(
                    "Unexpected user id in add proposal: {}",
                    incoming_user_id
                  ));
                }
              }

              commit_adds_members = true;
            } else if let Proposal::Remove(remove_proposal) = proposal.proposal() {
              let leaf_index = remove_proposal.removed();
              let member = group.member(leaf_index);
              let outgoing_user_id = {
                if let Some(member) = member {
                  u64::from_be_bytes(
                    member
                      .serialized_content()
                      .try_into()
                      .unwrap_or([0, 0, 0, 0, 0, 0, 0, 0]),
                  )
                } else {
                  0u64
                }
              };
              debug!(
                "Storing remove proposal for user {:?} (leaf index: {:?})",
                outgoing_user_id,
                leaf_index.u32()
              );
            }
            group
              .store_pending_proposal(self.provider.storage(), *proposal)
              .map_err(|err| napi_error!("Could not store proposal: {err}"))?;
          }
          _ => return Err(napi_error!("ProcessedMessage is not a ProposalMessage")),
        }
      }
    } else {
      let mut remaining_bytes: &[u8] = &proposals;
      while !remaining_bytes.is_empty() {
        let (proposal_ref, leftover) = ProposalRef::tls_deserialize_bytes(remaining_bytes)
          .map_err(|err| napi_error!("Error deserializing proposal ref: {err}"))?;
        remaining_bytes = leftover;

        debug!("Removing pending proposal {:?}", proposal_ref);
        group
          .remove_pending_proposal(self.provider.storage(), &proposal_ref)
          .map_err(|err| napi_error!("Error revoking proposal: {err}"))?;
      }
    }

    // Revert to previous state if there arent any more pending proposals
    let queued_proposal = group.pending_proposals().next();
    if queued_proposal.is_none() {
      debug!("No proposals left to commit, reverting to previous state");
      group
        .clear_pending_commit(self.provider.storage())
        .map_err(|err| napi_error!("Error removing previously pending commit: {err}"))?;
      if self.status == SessionStatus::AWAITING_RESPONSE {
        self.status = {
          if self.ready {
            SessionStatus::ACTIVE
          } else {
            SessionStatus::PENDING
          }
        }
      }
      return Ok(ProposalsResult {
        commit: None,
        welcome: None,
      });
    }

    // libdave seems to overwrite pendingGroupCommit_ and then not use it anywhere else...
    if group.pending_commit().is_some() {
      warn!("A pending commit was already created! Removing...");
      group
        .clear_pending_commit(self.provider.storage())
        .map_err(|err| napi_error!("Error removing previously pending commit: {err}"))?;
    }

    let (commit, welcome, _group_info) = group
      .commit_to_pending_proposals(&self.provider, &self.signer)
      .map_err(|err| napi_error!("Error committing pending proposals: {err}"))?;

    self.status = SessionStatus::AWAITING_RESPONSE;

    let mut welcome_buffer: Option<Buffer> = None;

    if commit_adds_members {
      match welcome {
        Some(mls_message_out) => match mls_message_out.body() {
          MlsMessageBodyOut::Welcome(welcome) => {
            welcome_buffer =
              Some(Buffer::from(welcome.tls_serialize_detached().map_err(
                |err| napi_error!("Error serializing welcome: {err}"),
              )?))
          }
          _ => return Err(napi_error!("MLSMessage was not a Welcome")),
        },
        _ => {
          return Err(napi_error!(
            "Welcome was not returned when there are new members"
          ))
        }
      }
    }

    let commit_buffer = commit
      .tls_serialize_detached()
      .map_err(|err| napi_error!("Error serializing commit: {err}"))?;

    Ok(ProposalsResult {
      commit: Some(Buffer::from(commit_buffer)),
      welcome: welcome_buffer,
    })
  }

  /// Process a welcome message.
  /// @param welcome The welcome message to process.
  /// @throws Will throw an error if the welcome is invalid. Send an [opcode 31: dave_mls_invalid_commit_welcome](https://daveprotocol.com/#dave_mls_invalid_commit_welcome-31) if this occurs.
  /// @see https://daveprotocol.com/#dave_mls_welcome-30
  #[napi]
  pub fn process_welcome(&mut self, welcome: Buffer) -> napi::Result<()> {
    if self.group.is_some() && self.status == SessionStatus::ACTIVE {
      return Err(napi_error!(
        "Cannot process a welcome after being in an established group"
      ));
    }

    if self.external_sender.is_none() {
      return Err(napi_error!(
        "Cannot process a welcome without an external sender"
      ));
    }

    // TODO we are skipping using recognized user IDs in here for now
    // See https://github.com/discord/libdave/blob/6e5ffbc1cb4eef6be96e8115c4626be598b7e501/cpp/src/dave/mls/session.cpp#L519

    debug!("Processing welcome");

    let mls_group_config = MlsGroupJoinConfig::builder()
      .use_ratchet_tree_extension(true)
      .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
      .build();

    let welcome = Welcome::tls_deserialize_exact_bytes(&welcome)
      .map_err(|err| napi_error!("Error deserializing welcome: {err}"))?;

    let staged_join =
      StagedWelcome::new_from_welcome(&self.provider, &mls_group_config, welcome, None)
        .map_err(|err| napi_error!("Error constructing staged join: {err}"))?;

    let external_senders = staged_join.group_context().extensions().external_senders();
    if external_senders.is_none() {
      return Err(napi_error!(
        "Welcome is missing an external senders extension"
      ));
    }

    let external_senders = external_senders.unwrap();
    if external_senders.len() != 1 {
      return Err(napi_error!(
        "Welcome lists an unexpected amount of external senders"
      ));
    }

    if external_senders.first().unwrap() != self.external_sender.as_ref().unwrap() {
      return Err(napi_error!("Welcome lists an unexpected external sender"));
    }

    let group = staged_join
      .into_group(&self.provider)
      .map_err(|err| napi_error!("Error joining group from staged welcome: {err}"))?;

    if self.group.is_some() {
      let mut pending_group = self.group.take().unwrap();
      pending_group
        .delete(self.provider.storage())
        .map_err(|err| napi_error!("Error clearing pending group: {err}"))?;
    }

    debug!(
      "Welcomed to group successfully, our leaf index is {:?}, our epoch is {:?}",
      group.own_leaf_index().u32(),
      group.epoch().as_u64()
    );
    self.group = Some(group);
    self.status = SessionStatus::ACTIVE;
    self.update_ratchets()?;

    Ok(())
  }

  /// Process a commit.
  /// @param commit The commit to process.
  /// @throws Will throw an error if the commit is invalid. Send an [opcode 31: dave_mls_invalid_commit_welcome](https://daveprotocol.com/#dave_mls_invalid_commit_welcome-31) if this occurs.
  /// @see https://daveprotocol.com/#dave_mls_announce_commit_transition-29
  #[napi]
  pub fn process_commit(&mut self, commit: Buffer) -> napi::Result<()> {
    if self.group.is_none() {
      return Err(napi_error!("Cannot process commit without a group"));
    }

    if self.group.is_some() && self.status == SessionStatus::PENDING {
      return Err(napi_error!("Cannot process commit for a pending group"));
    }

    debug!("Processing commit");

    let group = self.group.as_mut().unwrap();

    let mls_message = MlsMessageIn::tls_deserialize_exact_bytes(&commit)
      .map_err(|err| napi_error!("Error deserializing MLS message: {err}"))?;

    let protocol_message = mls_message
      .try_into_protocol_message()
      .map_err(|_| napi_error!("MLSMessage did not have a PublicMessage"))?;

    if protocol_message.group_id().as_slice() != self.group_id.as_slice() {
      return Err(napi_error!("MLSMessage was for a different group"));
    }

    let processed_message_result = group.process_message(&self.provider, protocol_message);

    if processed_message_result.is_err()
      && ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)
        == *processed_message_result.as_ref().unwrap_err()
    {
      // This is our own commit, lets merge pending instead
      debug!("Found own commit, merging pending commit instead.");
      group
        .merge_pending_commit(&self.provider)
        .map_err(|err| napi_error!("Error merging pending commit: {err}"))?;
    } else {
      // Someone elses commit, go through the usual stuff
      let processed_message =
        processed_message_result.map_err(|err| napi_error!("Could not process message: {err}"))?;

      match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
          group
            .merge_staged_commit(&self.provider, *staged_commit)
            .map_err(|err| napi_error!("Could not stage commit: {err}"))?;
        }
        _ => return Err(napi_error!("ProcessedMessage is not a StagedCommitMessage")),
      }
    }

    debug!(
      "Commit processed successfully, our leaf index is {:?}, our epoch is {:?}",
      group.own_leaf_index().u32(),
      group.epoch().as_u64()
    );
    self.status = SessionStatus::ACTIVE;
    self.update_ratchets()?;

    Ok(())
  }

  /// Get the verification code of another member of the group.
  /// This is the equivalent of `generateDisplayableCode(getPairwiseFingerprint(0, userId), 45, 5)`.
  /// @see https://daveprotocol.com/#displayable-codes
  #[napi(ts_return_type = "Promise<Buffer>")]
  pub fn get_verification_code(&self, user_id: String) -> AsyncTask<AsyncSessionVerificationCode> {
    let result = self.get_pairwise_fingerprint_internal(0, user_id);
    let (ok, err) = {
      match result {
        Ok(value) => (Some(value), None),
        Err(err) => (None, Some(err)),
      }
    };
    AsyncTask::new(AsyncSessionVerificationCode {
      fingerprints: ok,
      error: err,
    })
  }

  /// Create a pairwise fingerprint of you and another member.
  /// @see https://daveprotocol.com/#verification-fingerprint
  #[napi(ts_return_type = "Promise<Buffer>")]
  pub fn get_pairwise_fingerprint(
    &self,
    version: u16,
    user_id: String,
  ) -> AsyncTask<AsyncPairwiseFingerprintSession> {
    let result = self.get_pairwise_fingerprint_internal(version, user_id);
    let (ok, err) = {
      match result {
        Ok(value) => (Some(value), None),
        Err(err) => (None, Some(err)),
      }
    };
    AsyncTask::new(AsyncPairwiseFingerprintSession {
      fingerprints: ok,
      error: err,
    })
  }

  fn get_pairwise_fingerprint_internal(
    &self,
    version: u16,
    user_id: String,
  ) -> napi::Result<Vec<Vec<u8>>> {
    if self.group.is_none() || self.status == SessionStatus::PENDING {
      return Err(napi_error!(
        "Cannot get fingerprint without an established group"
      ));
    }

    let our_uid = self.user_id_as_u64()?;

    let their_uid = user_id
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;

    let member = self.group.as_ref().unwrap().members().find(|member| {
      let uid = u64::from_be_bytes(
        member
          .credential
          .serialized_content()
          .try_into()
          .unwrap_or([0, 0, 0, 0, 0, 0, 0, 0]),
      );
      uid == their_uid
    });

    if member.is_none() {
      return Err(napi_error!("Cannot find member in group"));
    }

    let member = member.unwrap();

    let fingerprints = vec![
      generate_key_fingerprint(version, our_uid, self.signer.public().to_vec()),
      generate_key_fingerprint(version, their_uid, member.signature_key),
    ];

    Ok(fingerprints)
  }

  fn update_ratchets(&mut self) -> napi::Result<()> {
    if self.group.is_none() {
      return Err(napi_error!("Cannot update ratchets without a group"));
    }
    let group = self.group.as_ref().unwrap();
    debug!(
      "Updating MLS ratchets for {:?} users",
      group.members().count()
    );

    // Update decryptors
    for member in group.members() {
      let user_id_bytes = TryInto::<[u8; 8]>::try_into(member.credential.serialized_content());
      if user_id_bytes.is_err() {
        warn!("Failed to get uid for member index {:?}", member.index);
        continue;
      }
      let uid = u64::from_be_bytes(user_id_bytes.unwrap());

      let ratchet = self.get_key_ratchet(uid)?;
      let decryptor = self.decryptors.entry(uid).or_insert_with(|| {
        debug!("Creating decryptor for user {uid:?}");
        Decryptor::new()
      });
      decryptor.transition_to_key_ratchet(ratchet);
    }

    // Update encryptor
    let user_id = self.user_id_as_u64()?;
    self
      .encryptor
      .set_key_ratchet(self.get_key_ratchet(user_id)?);

    // Update privacy code
    let old_code = self.privacy_code.clone();
    let epoch_authenticator = self.group.as_ref().unwrap().epoch_authenticator();
    self.privacy_code = generate_displayable_code_internal(epoch_authenticator.as_slice(), 30, 5)?;
    if self.privacy_code != old_code {
      debug!("New Voice Privacy Code: {:?}", self.privacy_code);
    }

    self.ready = true;

    Ok(())
  }

  /// @see https://daveprotocol.com/#sender-key-derivation
  fn get_key_ratchet(&self, user_id: u64) -> napi::Result<HashRatchet> {
    if self.group.is_none() || self.status == SessionStatus::PENDING {
      return Err(napi_error!(
        "Cannot get key ratchet without an established group"
      ));
    }

    let base_secret = self
      .group
      .as_ref()
      .unwrap()
      .export_secret(
        &self.provider,
        USER_MEDIA_KEY_BASE_LABEL,
        &user_id.to_le_bytes(),
        AES_GCM_128_KEY_BYTES,
      )
      .map_err(|err| napi_error!("Failed to export secret: {err}"))?;

    trace!("Got base secret for user {:?}: {:?}", user_id, base_secret);
    Ok(HashRatchet::new(base_secret))
  }

  /// Encrypt a packet with E2EE.
  /// @param mediaType The type of media to encrypt
  /// @param codec The codec of the packet
  /// @param packet The packet to encrypt
  #[napi]
  pub fn encrypt(
    &mut self,
    media_type: MediaType,
    codec: Codec,
    packet: Buffer,
  ) -> napi::Result<Buffer> {
    if !self.ready {
      return Err(napi_error!("Session is not ready to process frames"));
    }

    // Return the packet back to the client (passthrough) if the packet is a silence packet
    // This may change in the future, see: https://daveprotocol.com/#silence-packets
    if packet.len() == OPUS_SILENCE_PACKET.len() && packet.to_vec() == OPUS_SILENCE_PACKET.to_vec()
    {
      return Ok(packet);
    }

    let mut out_size: usize = 0;
    let mut encrypted_buffer =
      vec![0u8; Encryptor::get_max_ciphertext_byte_size(&media_type, packet.len())];

    let success = self.encryptor.encrypt(
      &media_type,
      codec,
      &packet,
      &mut encrypted_buffer,
      &mut out_size,
    );
    encrypted_buffer.resize(out_size, 0);
    if !success {
      return Err(napi_error!("DAVE encryption failure"));
    }

    Ok(encrypted_buffer.into())
  }

  /// Encrypt an opus packet to E2EE.
  /// This is the shorthand for `encrypt(MediaType.AUDIO, Codec.OPUS, packet)`
  /// @param packet The packet to encrypt
  #[napi]
  pub fn encrypt_opus(&mut self, packet: Buffer) -> napi::Result<Buffer> {
    self.encrypt(MediaType::AUDIO, Codec::OPUS, packet)
  }

  /// Get encryption stats.
  /// @param [mediaType=MediaType.AUDIO] The media type, defaults to `MediaType.AUDIO`
  #[napi]
  pub fn get_encryption_stats(
    &self,
    media_type: Option<MediaType>,
  ) -> napi::Result<EncryptionStats> {
    self
      .encryptor
      .stats
      .get(&media_type.unwrap_or(MediaType::AUDIO))
      .ok_or(napi_error!("Stats not found for that media type"))
      .cloned()
  }

  /// Decrypt an E2EE packet.
  /// @param userId The user ID of the packet
  /// @param mediaType The type of media to decrypt
  /// @param packet The packet to decrypt
  #[napi]
  pub fn decrypt(
    &mut self,
    user_id: String,
    media_type: MediaType,
    packet: Buffer,
  ) -> napi::Result<Buffer> {
    let uid = user_id
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;

    let decryptor = self.decryptors.get_mut(&uid);
    if decryptor.is_none() {
      return Err(napi_error!("No decryptor found for that user"));
    }
    let decryptor = decryptor.unwrap();

    let mut frame = vec![0u8; Decryptor::get_max_plaintext_byte_size(&media_type, packet.len())];
    let frame_length = decryptor.decrypt(&media_type, &packet, &mut frame);
    frame.resize(frame_length, 0);
    if frame_length == 0 {
      return Err(napi_error!("DAVE decryption failure"));
    }

    Ok(frame.into())
  }

  /// Get decryption stats.
  /// @param userId The user ID
  /// @param [mediaType=MediaType.AUDIO] The media type, defaults to `MediaType.AUDIO`
  #[napi]
  pub fn get_decryption_stats(
    &self,
    user_id: String,
    media_type: Option<MediaType>,
  ) -> napi::Result<DecryptionStats> {
    let uid = user_id
      .parse::<u64>()
      .map_err(|_| napi_invalid_arg_error!("Invalid user id"))?;

    let decryptor = self.decryptors.get(&uid);
    if decryptor.is_none() {
      return Err(napi_error!("No decryptor found for that user"));
    }

    decryptor
      .unwrap()
      .stats
      .get(&media_type.unwrap_or(MediaType::AUDIO))
      .ok_or(napi_error!("Stats not found for that media type"))
      .cloned()
  }

  /// Get the IDs of the users in the current group.
  /// @returns An array of user IDs, or an empty array if there is no group.
  #[napi]
  pub fn get_user_ids(&self) -> napi::Result<Vec<String>> {
    if self.group.is_none() {
      return Ok(vec![]);
    }

    let user_ids = self
      .group
      .as_ref()
      .unwrap()
      .members()
      .map(|member| {
        let uid = u64::from_be_bytes(
          member
            .credential
            .serialized_content()
            .try_into()
            .unwrap_or([0, 0, 0, 0, 0, 0, 0, 0]),
        );
        uid.to_string()
      })
      .collect();

    Ok(user_ids)
  }

  /// @ignore
  #[napi]
  pub fn to_string(&self) -> napi::Result<String> {
    Ok(format!(
      "DAVESession {{ protocolVersion: {}, userId: {}, channelId: {}, ready: {}, status: {:?} }}",
      self.protocol_version()?,
      self.user_id()?,
      self.channel_id()?,
      self.ready,
      self.status
    ))
  }
}
