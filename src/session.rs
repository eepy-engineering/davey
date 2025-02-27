use std::{array::TryFromSliceError, sync::Arc};
use napi::{bindgen_prelude::{AsyncTask, Buffer}, Error, Status};
use openmls::{group::*, prelude::{hash_ref::ProposalRef, tls_codec::Serialize, *}};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use log::{debug, warn};

use crate::{cryptor::hash_ratchet::HashRatchet, generate_displayable_code_internal, AsyncPairwiseFingerprintSession, AsyncSessionVerificationCode};

type DAVEProtocolVersion = u16;
const USER_MEDIA_KEY_BASE_LABEL: &str = "Discord Secure Frames v0";

/// Gets the [`Ciphersuite`] for a [`DAVEProtocolVersion`].
pub fn dave_protocol_version_to_ciphersuite(protocol_version: DAVEProtocolVersion) -> Result<Ciphersuite, Error> {
  match protocol_version {
    1 => Ok(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
    _ => Err(Error::from_reason("Unsupported protocol version".to_string())),
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
    _ => Err(Error::from_reason("Unsupported protocol version".to_string())),
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
#[derive(Debug,PartialEq)]
pub enum ProposalsOperationType {
  APPEND = 0,
  REVOKE = 1
}

#[napi]
#[derive(Debug,PartialEq)]
#[allow(non_camel_case_types)]
pub enum SessionStatus {
  INACTIVE = 0,
  PENDING = 1,
  AWAITING_RESPONSE = 2,
  ACTIVE = 3
}

#[napi(object)]
pub struct ProposalsResult {
	pub commit: Option<Buffer>,
	pub welcome: Option<Buffer>,
}

#[napi(js_name = "DAVESession")]
pub struct DaveSession {
  protocol_version: DAVEProtocolVersion,
  provider: Arc<OpenMlsRustCrypto>,
  ciphersuite: Ciphersuite,
  group_id: GroupId,
  signer: SignatureKeyPair,
  credential_with_key: CredentialWithKey,

  external_sender: Option<ExternalSender>,
  group: Option<MlsGroup>,
  status: SessionStatus
}

// TODO allow for specifying a signing key

#[napi]
impl DaveSession {
  /// @param protocolVersion The protocol version to use.
  /// @param userId The user ID of the session.
  /// @param channelId The channel ID of the session.
  #[napi(constructor)]
  pub fn new(protocol_version: u16, user_id: String, channel_id: String) -> napi::Result<Self> {
    let ciphersuite = dave_protocol_version_to_ciphersuite(protocol_version)?;
    let credential = BasicCredential::new(user_id.parse::<u64>()
      .map_err(|_| Error::new(Status::InvalidArg, "Invalid user id".to_string()))?.to_be_bytes().into());
    let group_id = GroupId::from_slice(&channel_id.parse::<u64>()
      .map_err(|_| Error::new(Status::InvalidArg, "Invalid channel id".to_string()))?.to_be_bytes());
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
      .map_err(|err| Error::from_reason(format!("Error generating a signature key pair: {err}")))?;
    let credential_with_key = CredentialWithKey {
      credential: credential.into(),
      signature_key: signer.public().into(),
    };

    Ok(DaveSession {
      protocol_version,
      ciphersuite,
      provider: Arc::new(OpenMlsRustCrypto::default()),
      group_id,
      signer,
      credential_with_key,
      external_sender: None,
      group: None,
      status: SessionStatus::INACTIVE
    })
  }

  /// Resets and re-initializes the session.
  /// @param protocolVersion The protocol version to use.
  /// @param userId The user ID of the session.
  /// @param channelId The channel ID of the session.
  #[napi]
  pub fn reinit(&mut self, protocol_version: u16, user_id: String, channel_id: String) -> napi::Result<()> {
    self.reset()?;
  
    let ciphersuite = dave_protocol_version_to_ciphersuite(protocol_version)?;
    let credential = BasicCredential::new(user_id.parse::<u64>()
      .map_err(|_| Error::new(Status::InvalidArg, "Invalid user id".to_string()))?.to_be_bytes().into());
    let group_id = GroupId::from_slice(&channel_id.parse::<u64>()
      .map_err(|_| Error::new(Status::InvalidArg, "Invalid channel id".to_string()))?.to_be_bytes());
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
      .map_err(|err| Error::from_reason(format!("Error generating a signature key pair: {err}")))?;
    let credential_with_key = CredentialWithKey {
      credential: credential.into(),
      signature_key: signer.public().into(),
    };

    self.protocol_version = protocol_version;
    self.ciphersuite = ciphersuite;
    self.group_id = group_id;
    self.signer = signer;
    self.credential_with_key = credential_with_key;

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
      self.group.take().unwrap()
        .delete(self.provider.storage())
        .map_err(|err| Error::from_reason(format!("Error clearing group: {err}")))?;
    }
    
    // Clear storage
    self.provider.storage().values.write()
      .map_err(|err| Error::from_reason(format!("MemoryStorage error: {err}")))?
      .clear();

    self.status = SessionStatus::INACTIVE;

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

  /// The status of this session.
  #[napi(getter)]
  pub fn status(&self) -> napi::Result<SessionStatus> {
    Ok(self.status)
  }

  /// Whether this session's group was created.
  #[napi(getter)]
  pub fn group_created(&self) -> napi::Result<bool> {
    Ok(self.group.is_some())
  }

  /// Get the epoch authenticator of this session's group.
  #[napi]
  pub fn get_epoch_authenticator(&self) -> napi::Result<Buffer> {
    if self.group.is_none() || self.status == SessionStatus::PENDING {
      return Err(Error::from_reason("Cannot epoch authenticator without an established MLS group".to_string()));
    }

    Ok(Buffer::from(self.group.as_ref().unwrap().epoch_authenticator().as_slice()))
  }

  /// Set the external sender this session will recieve from.
  /// @param externalSenderData The serialized external sender data.
  /// @throws Will throw if the external sender is invalid, or if the group has been established already.
  /// @see https://daveprotocol.com/#dave_mls_external_sender_package-25
  #[napi]
  pub fn set_external_sender(&mut self, external_sender_data: Buffer) -> napi::Result<()> {
    if self.status == SessionStatus::AWAITING_RESPONSE || self.status == SessionStatus::ACTIVE {
      return Err(Error::from_reason("Cannot set an external sender after joining an established group".to_string()));
    }

    let external_sender = ExternalSender::tls_deserialize_exact_bytes(&external_sender_data)
      .map_err(|err| Error::from_reason(format!("Failed to deserialize external sender: {err}")))?;

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
        .map_err(|err| Error::from_reason(format!("Error deserializing lifetime: {err}")))?
    };

    // This key package is stored in the provider for later
    let key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(dave_protocol_version_to_capabilities(self.protocol_version).unwrap())
        .key_package_lifetime(lifetime)
        .build(self.ciphersuite, self.provider.as_ref(), &self.signer, self.credential_with_key.clone())
        .map_err(|err| Error::from_reason(format!("Error creating key package: {err}")))?;

    let buffer = key_package.key_package().tls_serialize_detached()
      .map_err(|err| Error::from_reason(format!("Error serializing key package: {err}")))?;

    debug!("Created key package for channel {:?}.", self.channel_id().ok().unwrap_or_default());

    Ok(Buffer::from(buffer))
  }

  fn create_pending_group(&mut self) -> napi::Result<()> {
    if self.external_sender.is_none() {
      return Err(Error::from_reason("No external sender set".to_string()));
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
        self.provider.as_ref(),
        &self.signer,
        &mls_group_create_config,
        self.group_id.clone(),
        self.credential_with_key.clone(),
      )
      .map_err(|err| Error::from_reason(format!("Error creating a group: {err}")))?;

    self.group = Some(group);
    self.status = SessionStatus::PENDING;

    debug!("Created pending group for channel {:?}.", self.channel_id().ok().unwrap_or_default());

    Ok(())
  }

  // TODO add recognized user IDs in processProposals call
  /// Process proposals from an opcode 27 payload.
  /// @param operationType The operation type of the proposals.
  /// @param proposals The vector of proposals or proposal refs of the payload. (depending on operation type)
  /// @returns A commit (if there were queued proposals) and a welcome (if a member was added) that should be used to send an [opcode 28: dave_mls_commit_welcome](https://daveprotocol.com/#dave_mls_commit_welcome-28) ONLY if a commit was returned.
  /// @see https://daveprotocol.com/#dave_mls_proposals-27
  #[napi]
  pub fn process_proposals(&mut self, operation_type: ProposalsOperationType, proposals: Buffer) -> napi::Result<ProposalsResult> {
    if self.group.is_none() {
      return Err(Error::from_reason("Cannot process proposals without a group".to_string()));
    }

    let group = self.group.as_mut().unwrap();

    debug!("Processing proposals, optype {:?}", operation_type);

    let proposals: Vec<u8> = VLBytes::tls_deserialize_exact_bytes(&proposals)
      .map_err(|err| Error::from_reason(format!("Error deserializing proposal vector: {err}")))?
      .into();
    let mut commit_adds_members = false;

    if operation_type == ProposalsOperationType::APPEND {
      let mut remaining_bytes: &[u8] = &proposals;
      while remaining_bytes.len() != 0 {
        let (mls_message, leftover) =
          MlsMessageIn::tls_deserialize_bytes(&remaining_bytes)
          .map_err(|err| Error::from_reason(format!("Error deserializing MLS message: {err}")))?;
        remaining_bytes = leftover;
  
        let protocol_message = mls_message
          .try_into_protocol_message()
          .map_err(|_| Error::from_reason("MLSMessage did not have a PublicMessage".to_string()))?;

        let processed_message = group
          .process_message(self.provider.as_ref(), protocol_message)
          .map_err(|err| Error::from_reason(format!("Could not process message: {err}")))?;

        match processed_message.into_content() {
          ProcessedMessageContent::ProposalMessage(proposal) => {
            if let Proposal::Add(add_proposal) = proposal.proposal() {
              let incoming_user_id = u64::from_be_bytes(
                add_proposal.key_package().leaf_node().credential().serialized_content().try_into()
                  .map_err(|err| Error::from_reason(format!("Failed to convert proposal user id: {err}")))?
              );
              debug!("Storing add proposal for user {:?}", incoming_user_id.to_string());
              commit_adds_members = true;
            } else if let Proposal::Remove(remove_proposal) = proposal.proposal() {
              let leaf_index = remove_proposal.removed();
              let member = group.member(leaf_index);
              let outgoing_user_id = {
                if member.is_some() {
                  u64::from_be_bytes(
                    member.unwrap().serialized_content().try_into()
                      .or::<TryFromSliceError>(Ok([0, 0, 0, 0, 0, 0, 0, 0])).unwrap()
                  )
                } else {
                  0u64
                }
              };
              debug!("Storing remove proposal for user {:?} (leaf index: {:?})", outgoing_user_id, leaf_index.u32());
            }
            group
              .store_pending_proposal(self.provider.storage(), *proposal)
              .map_err(|err| Error::from_reason(format!("Could not store proposal: {err}")))?;
          }
          _ => return Err(Error::from_reason("ProcessedMessage is not a ProposalMessage".to_string())),
        }
      }
    } else {
      let mut remaining_bytes: &[u8] = &proposals;
      while remaining_bytes.len() != 0 {
        let (proposal_ref, leftover) =
          ProposalRef::tls_deserialize_bytes(&remaining_bytes)
          .map_err(|err| Error::from_reason(format!("Error deserializing proposal ref: {err}")))?;
        remaining_bytes = leftover;

        debug!("Removing pending proposal {:?}", proposal_ref);
        group.remove_pending_proposal(self.provider.storage(), &proposal_ref)
          .map_err(|err| Error::from_reason(format!("Error revoking proposal: {err}")))?;
      }
    }

    // Revert to previous state if there arent any more pending proposals
    let queued_proposal = group.pending_proposals().next();
    if queued_proposal.is_none() {
      debug!("No proposals left to commit, reverting to previous state");
      group.clear_pending_commit(self.provider.storage())
        .map_err(|err| Error::from_reason(format!("Error removing previously pending commit: {err}")))?;
      if self.status == SessionStatus::AWAITING_RESPONSE {
        // FIXME should pending groups have revoked proposals and still be pending? id assume the voice server signals to recreate the group
        self.status = SessionStatus::ACTIVE
      }
      return Ok(ProposalsResult {
        commit: None,
        welcome: None
      })
    }

    // libdave seems to overwrite pendingGroupCommit_ and then not use it anywhere else...
    if group.pending_commit().is_some() {
      warn!("A pending commit was already created! Removing...");
      group.clear_pending_commit(self.provider.storage())
        .map_err(|err| Error::from_reason(format!("Error removing previously pending commit: {err}")))?;
    }

    let (commit, welcome, _group_info) = group
      .commit_to_pending_proposals(self.provider.as_ref(), &self.signer)
      .map_err(|err| Error::from_reason(format!("Error committing pending proposals: {err}")))?;

    self.status = SessionStatus::AWAITING_RESPONSE;

    let mut welcome_buffer: Option<Buffer> = None;

    if commit_adds_members {
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
            _ => return Err(Error::from_reason("MLSMessage was not a Welcome".to_string())),
          }
        },
        _ => return Err(Error::from_reason("Welcome was not returned when there are new members".to_string())),
      }
    }

    let commit_buffer = commit.tls_serialize_detached()
      .map_err(|err| Error::from_reason(format!("Error serializing commit: {err}")))?;

    Ok(ProposalsResult {
      commit: Some(Buffer::from(commit_buffer)),
      welcome: welcome_buffer
    })
  }

  /// Process a welcome message.
  /// @param welcome The welcome message to process.
  /// @see https://daveprotocol.com/#dave_mls_welcome-30
  #[napi]
  pub fn process_welcome(&mut self, welcome: Buffer) -> napi::Result<()> {
    if self.group.is_some() && self.status == SessionStatus::ACTIVE {
      return Err(Error::from_reason("Cannot process a welcome after being in an established group".to_string()))
    }

    if self.external_sender.is_none() {
      return Err(Error::from_reason("Cannot process a welcome without an external sender".to_string()))
    }
  
    debug!("Processing welcome");

    let mls_group_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();

    let welcome = Welcome::tls_deserialize_exact_bytes(&welcome)
      .map_err(|err| Error::from_reason(format!("Error deserializing welcome: {err}")))?;

    let staged_join = StagedWelcome::new_from_welcome(self.provider.as_ref(), &mls_group_config, welcome, None)
      .map_err(|err| Error::from_reason(format!("Error constructing staged join: {err}")))?;

    let external_senders = staged_join.group_context().extensions().external_senders();
    if external_senders.is_none() {
      return Err(Error::from_reason("Welcome is missing an external senders extension".to_string()))
    }

    let external_senders = external_senders.unwrap();
    if external_senders.len() != 1 {
      return Err(Error::from_reason("Welcome lists an unexpected amount of external senders".to_string()))
    }

    if external_senders.get(0).unwrap() != self.external_sender.as_ref().unwrap() {
      return Err(Error::from_reason("Welcome lists an unexpected external sender".to_string()))
    }

    let group = staged_join
      .into_group(self.provider.as_ref())
      .map_err(|err| Error::from_reason(format!("Error joining group from staged welcome: {err}")))?;

    if self.group.is_some() {
      let mut pending_group = self.group.take().unwrap();
      pending_group.delete(self.provider.storage())
        .map_err(|err| Error::from_reason(format!("Error clearing pending group: {err}")))?;
    }

    debug!("Welcomed to group successfully, our leaf index is {:?}, our epoch is {:?}", group.own_leaf_index().u32(), group.epoch().as_u64());
    self.group = Some(group);
    self.status = SessionStatus::ACTIVE;

    Ok(())
  }

  /// Process a commit.
  /// @param commit The commit to process.
  /// @see https://daveprotocol.com/#dave_mls_announce_commit_transition-29
  #[napi]
  pub fn process_commit(&mut self, commit: Buffer) -> napi::Result<()> {
    if self.group.is_none() {
      return Err(Error::from_reason("Cannot process commit without a group".to_string()));
    }

    if self.group.is_some() && self.status == SessionStatus::PENDING {
      return Err(Error::from_reason("Cannot process commit for a pending group".to_string()))
    }
  
    debug!("Processing commit");

    let group = self.group.as_mut().unwrap();

    let mls_message =
      MlsMessageIn::tls_deserialize_exact_bytes(&commit)
      .map_err(|err| Error::from_reason(format!("Error deserializing MLS message: {err}")))?;

    let protocol_message = mls_message
      .try_into_protocol_message()
      .map_err(|_| Error::from_reason("MLSMessage did not have a PublicMessage".to_string()))?;

    if protocol_message.group_id().as_slice() != self.group_id.as_slice() {
      return Err(Error::from_reason("MLSMessage was for a different group".to_string()))
    }

    let processed_message_result = group
      .process_message(self.provider.as_ref(), protocol_message);

    if processed_message_result.is_err() && ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit) == *processed_message_result.as_ref().unwrap_err() {
      // This is our own commit, lets merge pending instead
      debug!("Found own commit, merging pending commit instead.");
      group
        .merge_pending_commit(self.provider.as_ref())
        .map_err(|err| Error::from_reason(format!("Error merging pending commit: {err}")))?;
    } else {
      // Someone elses commit, go through the usual stuff
      let processed_message = processed_message_result
        .map_err(|err| Error::from_reason(format!("Could not process message: {err}")))?;

      match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
          group
            .merge_staged_commit(self.provider.as_ref(), *staged_commit)
            .map_err(|err| Error::from_reason(format!("Could not stage commit: {err}")))?;
        }
        _ => return Err(Error::from_reason("ProcessedMessage is not a StagedCommitMessage".to_string())),
      }
    }
  
    debug!("Commit processed successfully, our leaf index is {:?}, our epoch is {:?}", group.own_leaf_index().u32(), group.epoch().as_u64());
    self.status = SessionStatus::ACTIVE;

    Ok(())
  }

  /// Get the Voice Privacy Code of the session.
  /// This is the equivalent of `generateDisplayableCode(epochAuthenticator, 30, 5)`.
  /// @see https://daveprotocol.com/#displayable-codes
  #[napi]
  pub fn get_voice_privacy_code(&self) -> napi::Result<String> {
    if self.group.is_none() || self.status == SessionStatus::PENDING {
      return Err(Error::from_reason("Cannot epoch authenticator without an established MLS group".to_string()));
    }

    let epoch_authenticator = self.group.as_ref().unwrap().epoch_authenticator();

    Ok(generate_displayable_code_internal(epoch_authenticator.as_slice(), 30, 5)?)
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
    AsyncTask::new(AsyncSessionVerificationCode { fingerprints: ok, error: err })
  }

  /// Create a pairwise fingerprint of you and another member.
  /// @see https://daveprotocol.com/#verification-fingerprint
  #[napi(ts_return_type = "Promise<Buffer>")]
  pub fn get_pairwise_fingerprint(&self, version: u16, user_id: String) -> AsyncTask<AsyncPairwiseFingerprintSession> {
    let result = self.get_pairwise_fingerprint_internal(version, user_id);
    let (ok, err) = {
      match result {
        Ok(value) => (Some(value), None),
        Err(err) => (None, Some(err)),
      }
    };
    AsyncTask::new(AsyncPairwiseFingerprintSession { fingerprints: ok, error: err })
  }

  fn get_pairwise_fingerprint_internal(&self, version: u16, user_id: String) -> napi::Result<Vec<Vec<u8>>> {
    if self.group.is_none() || self.status == SessionStatus::PENDING {
      return Err(Error::from_reason("Cannot get fingerprint without an established group".to_string()))
    }

    let our_uid = 
      u64::from_be_bytes(
        self.credential_with_key.credential.serialized_content().try_into()
          .map_err(|err| Error::from_reason(format!("Failed to convert our user id: {err}")))?
      );

    let their_uid = user_id.parse::<u64>()
      .map_err(|_| Error::new(Status::InvalidArg, "Invalid user id".to_string()))?;

    let member = self.group.as_ref().unwrap().members().find(|member| {
      let uid = u64::from_be_bytes(
        member.credential.serialized_content().try_into().or::<TryFromSliceError>(Ok([0, 0, 0, 0, 0, 0, 0, 0])).unwrap()
      );
      uid == their_uid
    });

    if member.is_none() {
      return Err(Error::from_reason("Cannot find member in group".to_string()))
    }

    let member = member.unwrap();

    let fingerprints = vec![
      generate_key_fingerprint(version, our_uid, self.signer.public().to_vec()),
      generate_key_fingerprint(version, their_uid, member.signature_key)
    ];

    Ok(fingerprints)
  }

  /// @see https://daveprotocol.com/#sender-key-derivation
  pub fn get_key_ratchet(&self, user_id: String) -> napi::Result<()> {
    if self.group.is_none() || self.status == SessionStatus::PENDING {
      return Err(Error::from_reason("Cannot get key ratchet without an established group".to_string()))
    }

    let le_user_id = user_id.parse::<u64>()
      .map_err(|_| Error::new(Status::InvalidArg, "Invalid user id".to_string()))?
      .to_le_bytes();

    let base_secret = self.group.as_ref().unwrap().export_secret(self.provider.as_ref(), USER_MEDIA_KEY_BASE_LABEL, &le_user_id, 16)
      .map_err(|err| Error::from_reason(format!("Failed to export secret: {err}")))?;

    let hash_ratchet = HashRatchet::new(&base_secret, self.provider.clone(), self.ciphersuite);

    todo!();
  }

  /// The amount of items in memory storage.
  #[napi(getter)]
  pub fn items_in_storage(&self) -> napi::Result<i32> {
    let map_read_guard = self.provider.storage().values.read()
      .map_err(|err| Error::from_reason(format!("MemoryStorage error: {err}")))?;
    Ok(map_read_guard.len() as i32)
  }

  /// @ignore
  #[napi]
  pub fn to_string(&self) -> napi::Result<String> {
    Ok(format!(
      "DAVESession {{ protocolVersion: {}, userId: {}, channelId: {}, group_created: {}, status: {:?} }}",
      self.protocol_version()?, self.user_id()?, self.channel_id()?, self.group.is_some(), self.status
    ))
  }
}