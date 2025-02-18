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

  #[napi(getter)]
  pub fn protocol_version(&self) -> napi::Result<i32> {
    Ok(self.protocol_version as i32)
  }

  #[napi(getter)]
  pub fn user_id(&self) -> napi::Result<String> {
    Ok(
      u64::from_be_bytes(
        self.credential_with_key.credential.serialized_content().try_into()
          .map_err(|err| Error::from_reason(format!("Failed to convert user id: {err}")))?
      ).to_string()
    )
  }

  #[napi(getter)]
  pub fn channel_id(&self) -> napi::Result<String> {
    Ok(
      u64::from_be_bytes(
        self.group_id.as_slice().try_into()
        .map_err(|err| Error::from_reason(format!("Failed to convert channel id: {err}")))?
      ).to_string()
    )
  }

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
      .map_err(|err| Error::from_reason(format!("Error deserializing key package: {err}")))?;

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