// Copyright 2020 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(feature = "sled_cryptostore")]
use std::path::Path;
use std::{
    collections::{BTreeMap, HashSet},
    mem,
    sync::Arc,
};

use dashmap::DashMap;
use matrix_sdk_common::{
    deserialized_responses::{AlgorithmInfo, EncryptionInfo, SyncRoomEvent, VerificationState},
    locks::Mutex,
    uuid::Uuid,
};
use ruma::{
    api::client::r0::{
        keys::{
            claim_keys::{Request as KeysClaimRequest, Response as KeysClaimResponse},
            get_keys::Response as KeysQueryResponse,
            upload_keys,
            upload_signatures::Request as UploadSignaturesRequest,
        },
        sync::sync_events::{DeviceLists, ToDevice},
    },
    assign,
    events::{
        room::encrypted::{
            EncryptedEventContent, EncryptedEventScheme, EncryptedToDeviceEventContent,
        },
        room_key::RoomKeyToDeviceEventContent,
        secret::request::SecretName,
        AnyMessageEventContent, AnyRoomEvent, AnyToDeviceEvent, SyncMessageEvent, ToDeviceEvent,
    },
    DeviceId, DeviceIdBox, DeviceKeyAlgorithm, EventEncryptionAlgorithm, RoomId, UInt, UserId,
};
use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "sled_cryptostore")]
use crate::store::sled::SledStore;
use crate::{
    error::{EventError, MegolmError, MegolmResult, OlmError, OlmResult},
    gossiping::GossipMachine,
    identities::{user::UserIdentities, Device, IdentityManager, UserDevices},
    olm::{
        Account, CrossSigningStatus, EncryptionSettings, ExportedRoomKey, GroupSessionKey,
        IdentityKeys, InboundGroupSession, OlmDecryptionInfo, PrivateCrossSigningIdentity,
        ReadOnlyAccount, SessionType,
    },
    requests::{IncomingResponse, OutgoingRequest, UploadSigningKeysRequest},
    session_manager::{GroupSessionManager, SessionManager},
    store::{
        Changes, CryptoStore, DeviceChanges, IdentityChanges, MemoryStore, Result as StoreResult,
        SecretImportError, Store,
    },
    verification::{Verification, VerificationMachine, VerificationRequest},
    CrossSigningKeyExport, ToDeviceRequest,
};

/// State machine implementation of the Olm/Megolm encryption protocol used for
/// Matrix end to end encryption.
#[derive(Clone)]
pub struct OlmMachine {
    /// The unique user id that owns this account.
    user_id: Arc<UserId>,
    /// The unique device id of the device that holds this account.
    device_id: Arc<DeviceId>,
    /// Our underlying Olm Account holding our identity keys.
    account: Account,
    /// The private part of our cross signing identity.
    /// Used to sign devices and other users, might be missing if some other
    /// device bootstrapped cross signing or cross signing isn't bootstrapped at
    /// all.
    user_identity: Arc<Mutex<PrivateCrossSigningIdentity>>,
    /// Store for the encryption keys.
    /// Persists all the encryption keys so a client can resume the session
    /// without the need to create new keys.
    store: Store,
    /// A state machine that handles Olm sessions creation.
    session_manager: SessionManager,
    /// A state machine that keeps track of our outbound group sessions.
    group_session_manager: GroupSessionManager,
    /// A state machine that is responsible to handle and keep track of SAS
    /// verification flows.
    verification_machine: VerificationMachine,
    /// The state machine that is responsible to handle outgoing and incoming
    /// key requests.
    key_request_machine: GossipMachine,
    /// State machine handling public user identities and devices, keeping track
    /// of when a key query needs to be done and handling one.
    identity_manager: IdentityManager,
    cross_signing_request: Arc<Mutex<Option<UploadSignaturesRequest>>>,
}

#[cfg(not(tarpaulin_include))]
impl std::fmt::Debug for OlmMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OlmMachine")
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .finish()
    }
}

impl OlmMachine {
    /// Create a new memory based OlmMachine.
    ///
    /// The created machine will keep the encryption keys only in memory and
    /// once the object is dropped the keys will be lost.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique id of the user that owns this machine.
    ///
    /// * `device_id` - The unique id of the device that owns this machine.
    pub fn new(user_id: &UserId, device_id: &DeviceId) -> Self {
        let store: Box<dyn CryptoStore> = Box::new(MemoryStore::new());
        let device_id: DeviceIdBox = device_id.into();
        let account = ReadOnlyAccount::new(user_id, &device_id);

        OlmMachine::new_helper(
            user_id,
            device_id,
            store,
            account,
            PrivateCrossSigningIdentity::empty(user_id.to_owned()),
        )
    }

    fn new_helper(
        user_id: &UserId,
        device_id: DeviceIdBox,
        store: Box<dyn CryptoStore>,
        account: ReadOnlyAccount,
        user_identity: PrivateCrossSigningIdentity,
    ) -> Self {
        let user_id = Arc::new(user_id.clone());
        let user_identity = Arc::new(Mutex::new(user_identity));

        let store: Arc<dyn CryptoStore> = store.into();
        let verification_machine =
            VerificationMachine::new(account.clone(), user_identity.clone(), store.clone());
        let store =
            Store::new(user_id.clone(), user_identity.clone(), store, verification_machine.clone());
        let device_id: Arc<DeviceId> = device_id.into();
        let users_for_key_claim = Arc::new(DashMap::new());

        let account = Account { inner: account, store: store.clone() };

        let group_session_manager = GroupSessionManager::new(account.clone(), store.clone());

        let key_request_machine = GossipMachine::new(
            user_id.clone(),
            device_id.clone(),
            store.clone(),
            group_session_manager.session_cache(),
            users_for_key_claim.clone(),
        );

        let session_manager = SessionManager::new(
            account.clone(),
            users_for_key_claim,
            key_request_machine.clone(),
            store.clone(),
        );
        let identity_manager =
            IdentityManager::new(user_id.clone(), device_id.clone(), store.clone());

        OlmMachine {
            user_id,
            device_id,
            account,
            user_identity,
            store,
            session_manager,
            group_session_manager,
            verification_machine,
            key_request_machine,
            identity_manager,
            cross_signing_request: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a new OlmMachine with the given [`CryptoStore`].
    ///
    /// The created machine will keep the encryption keys only in memory and
    /// once the object is dropped the keys will be lost.
    ///
    /// If the store already contains encryption keys for the given user/device
    /// pair those will be re-used. Otherwise new ones will be created and
    /// stored.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique id of the user that owns this machine.
    ///
    /// * `device_id` - The unique id of the device that owns this machine.
    ///
    /// * `store` - A `Cryptostore` implementation that will be used to store
    /// the encryption keys.
    ///
    /// [`Cryptostore`]: trait.CryptoStore.html
    pub async fn new_with_store(
        user_id: UserId,
        device_id: DeviceIdBox,
        store: Box<dyn CryptoStore>,
    ) -> StoreResult<Self> {
        let account = match store.load_account().await? {
            Some(a) => {
                debug!(ed25519_key = a.identity_keys().ed25519(), "Restored an Olm account");
                a
            }
            None => {
                let account = ReadOnlyAccount::new(&user_id, &device_id);
                debug!(
                    ed25519_key = account.identity_keys().ed25519(),
                    "Created a new Olm account"
                );
                store.save_account(account.clone()).await?;
                account
            }
        };

        let identity = match store.load_identity().await? {
            Some(i) => {
                let master_key = i
                    .master_public_key()
                    .await
                    .and_then(|m| m.get_first_key().map(|m| m.to_string()));
                debug!(
                    master_key =? master_key,
                    "Restored the cross signing identity"
                );
                i
            }
            None => {
                debug!("Creating an empty cross signing identity stub");
                PrivateCrossSigningIdentity::empty(user_id.clone())
            }
        };

        Ok(OlmMachine::new_helper(&user_id, device_id, store, account, identity))
    }

    /// Create a new machine with the default crypto store.
    ///
    /// The default store uses a Sled database to store the encryption keys.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique id of the user that owns this machine.
    ///
    /// * `device_id` - The unique id of the device that owns this machine.
    #[cfg(feature = "sled_cryptostore")]
    #[cfg_attr(feature = "docs", doc(cfg(sled_cryptostore)))]
    pub async fn new_with_default_store(
        user_id: &UserId,
        device_id: &DeviceId,
        path: impl AsRef<Path>,
        passphrase: Option<&str>,
    ) -> StoreResult<Self> {
        let store = SledStore::open_with_passphrase(path, passphrase)?;

        OlmMachine::new_with_store(user_id.to_owned(), device_id.into(), Box::new(store)).await
    }

    /// The unique user id that owns this `OlmMachine` instance.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The unique device id that identifies this `OlmMachine`.
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Get the public parts of our Olm identity keys.
    pub fn identity_keys(&self) -> &IdentityKeys {
        self.account.identity_keys()
    }

    /// Get the display name of our own device
    pub async fn dislpay_name(&self) -> StoreResult<Option<String>> {
        self.store.device_display_name().await
    }

    /// Get all the tracked users we know about
    pub fn tracked_users(&self) -> HashSet<UserId> {
        self.store.tracked_users()
    }

    /// Get the outgoing requests that need to be sent out.
    ///
    /// This returns a list of `OutGoingRequest`, those requests need to be sent
    /// out to the server and the responses need to be passed back to the state
    /// machine using [`mark_request_as_sent`].
    ///
    /// [`mark_request_as_sent`]: #method.mark_request_as_sent
    pub async fn outgoing_requests(&self) -> StoreResult<Vec<OutgoingRequest>> {
        let mut requests = Vec::new();

        if let Some(r) = self
            .keys_for_upload()
            .await
            .map(|r| OutgoingRequest { request_id: Uuid::new_v4(), request: Arc::new(r.into()) })
        {
            requests.push(r);
        }

        for request in
            self.identity_manager.users_for_key_query().await.into_iter().map(|r| OutgoingRequest {
                request_id: Uuid::new_v4(),
                request: Arc::new(r.into()),
            })
        {
            requests.push(request);
        }

        requests.append(&mut self.verification_machine.outgoing_messages());
        requests.append(&mut self.key_request_machine.outgoing_to_device_requests().await?);

        Ok(requests)
    }

    /// Mark the request with the given request id as sent.
    ///
    /// # Arguments
    ///
    /// * `request_id` - The unique id of the request that was sent out. This is
    /// needed to couple the response with the now sent out request.
    ///
    /// * `response` - The response that was received from the server after the
    /// outgoing request was sent out.
    pub async fn mark_request_as_sent<'a>(
        &self,
        request_id: &Uuid,
        response: impl Into<IncomingResponse<'a>>,
    ) -> OlmResult<()> {
        match response.into() {
            IncomingResponse::KeysUpload(response) => {
                self.receive_keys_upload_response(response).await?;
            }
            IncomingResponse::KeysQuery(response) => {
                self.receive_keys_query_response(response).await?;
            }
            IncomingResponse::KeysClaim(response) => {
                self.receive_keys_claim_response(response).await?;
            }
            IncomingResponse::ToDevice(_) => {
                self.mark_to_device_request_as_sent(request_id).await?;
            }
            IncomingResponse::SigningKeysUpload(_) => {
                self.receive_cross_signing_upload_response().await?;
            }
            IncomingResponse::SignatureUpload(_) => {
                self.verification_machine.mark_request_as_sent(request_id);
            }
            IncomingResponse::RoomMessage(_) => {
                self.verification_machine.mark_request_as_sent(request_id);
            }
        };

        Ok(())
    }

    /// Mark the cross signing identity as shared.
    async fn receive_cross_signing_upload_response(&self) -> StoreResult<()> {
        let identity = self.user_identity.lock().await;
        identity.mark_as_shared();

        let changes = Changes { private_identity: Some(identity.clone()), ..Default::default() };

        self.store.save_changes(changes).await
    }

    /// Create a new cross signing identity and get the upload request to push
    /// the new public keys to the server.
    ///
    /// **Warning**: This will delete any existing cross signing keys that might
    /// exist on the server and thus will reset the trust between all the
    /// devices.
    ///
    /// Uploading these keys will require user interactive auth.
    pub async fn bootstrap_cross_signing(
        &self,
        reset: bool,
    ) -> StoreResult<(UploadSigningKeysRequest, UploadSignaturesRequest)> {
        let mut identity = self.user_identity.lock().await;

        if identity.is_empty().await || reset {
            info!("Creating new cross signing identity");
            let (id, request, signature_request) = self.account.bootstrap_cross_signing().await;

            *identity = id;

            let public = identity.to_public_identity().await.expect(
                "Couldn't create a public version of the identity from a new private identity",
            );

            let changes = Changes {
                identities: IdentityChanges { new: vec![public.into()], ..Default::default() },
                private_identity: Some(identity.clone()),
                ..Default::default()
            };

            self.store.save_changes(changes).await?;

            Ok((request, signature_request))
        } else {
            info!("Trying to upload the existing cross signing identity");
            let request = identity.as_upload_request().await;
            // TODO remove this expect.
            let signature_request =
                identity.sign_account(&self.account).await.expect("Can't sign device keys");
            Ok((request, signature_request))
        }
    }

    /// Should device or one-time keys be uploaded to the server.
    ///
    /// This needs to be checked periodically, ideally after every sync request.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::convert::TryFrom;
    /// # use matrix_sdk_crypto::OlmMachine;
    /// # use ruma::UserId;
    /// # use futures::executor::block_on;
    /// # let alice = UserId::try_from("@alice:example.org").unwrap();
    /// # let machine = OlmMachine::new(&alice, "DEVICEID".into());
    /// # block_on(async {
    /// if machine.should_upload_keys().await {
    ///     let request = machine
    ///         .keys_for_upload()
    ///         .await
    ///         .unwrap();
    ///
    ///     // Upload the keys here.
    /// }
    /// # });
    /// ```
    #[cfg(test)]
    async fn should_upload_keys(&self) -> bool {
        self.account.should_upload_keys().await
    }

    /// Get the underlying Olm account of the machine.
    #[cfg(test)]
    pub(crate) fn account(&self) -> &ReadOnlyAccount {
        &self.account
    }

    /// Receive a successful keys upload response.
    ///
    /// # Arguments
    ///
    /// * `response` - The keys upload response of the request that the client
    /// performed.
    async fn receive_keys_upload_response(
        &self,
        response: &upload_keys::Response,
    ) -> OlmResult<()> {
        self.account.receive_keys_upload_response(response).await
    }

    /// Get the a key claiming request for the user/device pairs that we are
    /// missing Olm sessions for.
    ///
    /// Returns None if no key claiming request needs to be sent out.
    ///
    /// Sessions need to be established between devices so group sessions for a
    /// room can be shared with them.
    ///
    /// This should be called every time a group session needs to be shared as
    /// well as between sync calls. After a sync some devices may request room
    /// keys without us having a valid Olm session with them, making it
    /// impossible to server the room key request, thus it's necessary to check
    /// for missing sessions between sync as well.
    ///
    /// **Note**: Care should be taken that only one such request at a time is
    /// in flight, e.g. using a lock.
    ///
    /// The response of a successful key claiming requests needs to be passed to
    /// the `OlmMachine` with the [`mark_request_as_sent`].
    ///
    /// # Arguments
    ///
    /// `users` - The list of users that we should check if we lack a session
    /// with one of their devices. This can be an empty iterator when calling
    /// this method between sync requests.
    ///
    /// [`mark_request_as_sent`]: #method.mark_request_as_sent
    pub async fn get_missing_sessions(
        &self,
        users: impl Iterator<Item = &UserId>,
    ) -> StoreResult<Option<(Uuid, KeysClaimRequest)>> {
        self.session_manager.get_missing_sessions(users).await
    }

    /// Receive a successful key claim response and create new Olm sessions with
    /// the claimed keys.
    ///
    /// # Arguments
    ///
    /// * `response` - The response containing the claimed one-time keys.
    async fn receive_keys_claim_response(&self, response: &KeysClaimResponse) -> OlmResult<()> {
        self.session_manager.receive_keys_claim_response(response).await
    }

    /// Receive a successful keys query response.
    ///
    /// Returns a list of devices newly discovered devices and devices that
    /// changed.
    ///
    /// # Arguments
    ///
    /// * `response` - The keys query response of the request that the client
    /// performed.
    async fn receive_keys_query_response(
        &self,
        response: &KeysQueryResponse,
    ) -> OlmResult<(DeviceChanges, IdentityChanges)> {
        self.identity_manager.receive_keys_query_response(response).await
    }

    /// Get a request to upload E2EE keys to the server.
    ///
    /// Returns None if no keys need to be uploaded.
    ///
    /// The response of a successful key upload requests needs to be passed to
    /// the [`OlmMachine`] with the [`receive_keys_upload_response`].
    ///
    /// [`receive_keys_upload_response`]: #method.receive_keys_upload_response
    /// [`OlmMachine`]: struct.OlmMachine.html
    async fn keys_for_upload(&self) -> Option<upload_keys::Request> {
        let (device_keys, one_time_keys) = self.account.keys_for_upload().await?;
        Some(assign!(upload_keys::Request::new(), { device_keys, one_time_keys }))
    }

    /// Decrypt a to-device event.
    ///
    /// Returns a decrypted `ToDeviceEvent` if the decryption was successful,
    /// an error indicating why decryption failed otherwise.
    ///
    /// # Arguments
    ///
    /// * `event` - The to-device event that should be decrypted.
    async fn decrypt_to_device_event(
        &self,
        event: &ToDeviceEvent<EncryptedToDeviceEventContent>,
    ) -> OlmResult<OlmDecryptionInfo> {
        let mut decrypted = self.account.decrypt_to_device_event(event).await?;
        // Handle the decrypted event, e.g. fetch out Megolm sessions out of
        // the event.
        if let (Some(event), group_session) =
            self.handle_decrypted_to_device_event(&decrypted).await?
        {
            // Some events may have sensitive data e.g. private keys, while we
            // want to notify our users that a private key was received we
            // don't want them to be able to do silly things with it. Handling
            // events modifies them and returns a modified one, so replace it
            // here if we get one.
            decrypted.deserialized_event = Some(event);
            decrypted.inbound_group_session = group_session;
        }

        Ok(decrypted)
    }

    /// Create a group session from a room key and add it to our crypto store.
    async fn add_room_key(
        &self,
        sender_key: &str,
        signing_key: &str,
        event: &mut ToDeviceEvent<RoomKeyToDeviceEventContent>,
    ) -> OlmResult<(Option<AnyToDeviceEvent>, Option<InboundGroupSession>)> {
        match event.content.algorithm {
            EventEncryptionAlgorithm::MegolmV1AesSha2 => {
                let session_key = GroupSessionKey(mem::take(&mut event.content.session_key));

                let session = InboundGroupSession::new(
                    sender_key,
                    signing_key,
                    &event.content.room_id,
                    session_key,
                    None,
                )?;

                info!(
                    "Received a new room key from {} for room {} with session id {}",
                    event.sender,
                    event.content.room_id,
                    session.session_id()
                );
                let event = AnyToDeviceEvent::RoomKey(event.clone());
                Ok((Some(event), Some(session)))
            }
            _ => {
                warn!(
                    "Received room key with unsupported key algorithm {}",
                    event.content.algorithm
                );
                Ok((None, None))
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn create_outbound_group_session_with_defaults(
        &self,
        room_id: &RoomId,
    ) -> OlmResult<()> {
        let (_, session) = self
            .group_session_manager
            .create_outbound_group_session(room_id, EncryptionSettings::default())
            .await?;

        self.store.save_inbound_group_sessions(&[session]).await?;

        Ok(())
    }

    /// Encrypt a room message for the given room.
    ///
    /// Beware that a group session needs to be shared before this method can be
    /// called using the [`share_group_session`] method.
    ///
    /// Since group sessions can expire or become invalid if the room membership
    /// changes client authors should check with the
    /// [`should_share_group_session`] method if a new group session needs to
    /// be shared.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The id of the room for which the message should be
    /// encrypted.
    ///
    /// * `content` - The plaintext content of the message that should be
    /// encrypted.
    ///
    /// # Panics
    ///
    /// Panics if a group session for the given room wasn't shared beforehand.
    ///
    /// [`should_share_group_session`]: #method.should_share_group_session
    /// [`share_group_session`]: #method.share_group_session
    pub async fn encrypt(
        &self,
        room_id: &RoomId,
        content: AnyMessageEventContent,
    ) -> MegolmResult<EncryptedEventContent> {
        self.group_session_manager.encrypt(room_id, content).await
    }

    /// Invalidate the currently active outbound group session for the given
    /// room.
    ///
    /// Returns true if a session was invalidated, false if there was no session
    /// to invalidate.
    pub async fn invalidate_group_session(&self, room_id: &RoomId) -> StoreResult<bool> {
        self.group_session_manager.invalidate_group_session(room_id).await
    }

    /// Get to-device requests to share a group session with users in a room.
    ///
    /// # Arguments
    ///
    /// `room_id` - The room id of the room where the group session will be
    /// used.
    ///
    /// `users` - The list of users that should receive the group session.
    pub async fn share_group_session(
        &self,
        room_id: &RoomId,
        users: impl Iterator<Item = &UserId>,
        encryption_settings: impl Into<EncryptionSettings>,
    ) -> OlmResult<Vec<Arc<ToDeviceRequest>>> {
        self.group_session_manager.share_group_session(room_id, users, encryption_settings).await
    }

    /// Receive and properly handle a decrypted to-device event.
    ///
    /// # Arguments
    ///
    /// * `sender_key` - The sender (curve25519) key of the event sender.
    ///
    /// * `signing_key` - The signing (ed25519) key of the event sender.
    ///
    /// * `event` - The decrypted to-device event.
    async fn handle_decrypted_to_device_event(
        &self,
        decrypted: &OlmDecryptionInfo,
    ) -> OlmResult<(Option<AnyToDeviceEvent>, Option<InboundGroupSession>)> {
        let event = match decrypted.event.deserialize() {
            Ok(e) => e,
            Err(e) => {
                warn!("Decrypted to-device event failed to be parsed correctly {:?}", e);
                return Ok((None, None));
            }
        };

        match event {
            AnyToDeviceEvent::RoomKey(mut e) => {
                Ok(self.add_room_key(&decrypted.sender_key, &decrypted.signing_key, &mut e).await?)
            }
            AnyToDeviceEvent::ForwardedRoomKey(mut e) => Ok(self
                .key_request_machine
                .receive_forwarded_room_key(&decrypted.sender_key, &mut e)
                .await?),
            AnyToDeviceEvent::SecretSend(mut e) => Ok((
                self.key_request_machine.receive_secret(&decrypted.sender_key, &mut e).await?,
                None,
            )),
            _ => {
                warn!(event_type =? event.event_type(), "Received an unexpected encrypted to-device event");
                Ok((Some(event), None))
            }
        }
    }

    async fn handle_verification_event(&self, event: &AnyToDeviceEvent) {
        if let Err(e) = self.verification_machine.receive_any_event(event).await {
            error!("Error handling a verification event: {:?}", e);
        }
    }

    /// Mark an outgoing to-device requests as sent.
    async fn mark_to_device_request_as_sent(&self, request_id: &Uuid) -> StoreResult<()> {
        self.verification_machine.mark_request_as_sent(request_id);
        self.key_request_machine.mark_outgoing_request_as_sent(*request_id).await?;
        self.group_session_manager.mark_request_as_sent(request_id).await?;
        self.session_manager.mark_outgoing_request_as_sent(request_id);

        Ok(())
    }

    /// Get a verification object for the given user id with the given flow id.
    pub fn get_verification(&self, user_id: &UserId, flow_id: &str) -> Option<Verification> {
        self.verification_machine.get_verification(user_id, flow_id)
    }

    /// Get a verification request object with the given flow id.
    pub fn get_verification_request(
        &self,
        user_id: &UserId,
        flow_id: impl AsRef<str>,
    ) -> Option<VerificationRequest> {
        self.verification_machine.get_request(user_id, flow_id)
    }

    /// Get all the verification requests of a given user.
    pub fn get_verification_requests(&self, user_id: &UserId) -> Vec<VerificationRequest> {
        self.verification_machine.get_requests(user_id)
    }

    fn update_one_time_key_count(&self, key_count: &BTreeMap<DeviceKeyAlgorithm, UInt>) {
        self.account.update_uploaded_key_count(key_count);
    }

    async fn handle_to_device_event(&self, event: &AnyToDeviceEvent) {
        match event {
            AnyToDeviceEvent::RoomKeyRequest(e) => {
                self.key_request_machine.receive_incoming_key_request(e)
            }
            AnyToDeviceEvent::SecretRequest(e) => {
                self.key_request_machine.receive_incoming_secret_request(e)
            }
            AnyToDeviceEvent::KeyVerificationAccept(..)
            | AnyToDeviceEvent::KeyVerificationCancel(..)
            | AnyToDeviceEvent::KeyVerificationKey(..)
            | AnyToDeviceEvent::KeyVerificationMac(..)
            | AnyToDeviceEvent::KeyVerificationRequest(..)
            | AnyToDeviceEvent::KeyVerificationReady(..)
            | AnyToDeviceEvent::KeyVerificationDone(..)
            | AnyToDeviceEvent::KeyVerificationStart(..) => {
                self.handle_verification_event(event).await;
            }
            AnyToDeviceEvent::Dummy(_)
            | AnyToDeviceEvent::RoomKey(_)
            | AnyToDeviceEvent::ForwardedRoomKey(_)
            | AnyToDeviceEvent::RoomEncrypted(_) => {}
            _ => {}
        }
    }

    /// Handle a to-device and one-time key counts from a sync response.
    ///
    /// This will decrypt and handle to-device events returning the decrypted
    /// versions of them.
    ///
    /// To decrypt an event from the room timeline call [`decrypt_room_event`].
    ///
    /// # Arguments
    ///
    /// * `to_device_events` - The to-device events of the current sync
    /// response.
    ///
    /// * `changed_devices` - The list of devices that changed in this sync
    /// response.
    ///
    /// * `one_time_keys_count` - The current one-time keys counts that the sync
    /// response returned.
    ///
    /// [`decrypt_room_event`]: #method.decrypt_room_event
    pub async fn receive_sync_changes(
        &self,
        to_device_events: ToDevice,
        changed_devices: &DeviceLists,
        one_time_keys_counts: &BTreeMap<DeviceKeyAlgorithm, UInt>,
    ) -> OlmResult<ToDevice> {
        // Remove verification objects that have expired or are done.
        let mut events = self.verification_machine.garbage_collect();

        // Always save the account, a new session might get created which also
        // touches the account.
        let mut changes =
            Changes { account: Some(self.account.inner.clone()), ..Default::default() };

        self.update_one_time_key_count(one_time_keys_counts);

        for user_id in &changed_devices.changed {
            if let Err(e) = self.identity_manager.mark_user_as_changed(user_id).await {
                error!("Error marking a tracked user as changed {:?}", e);
            }
        }

        for mut raw_event in to_device_events.events {
            let event = match raw_event.deserialize() {
                Ok(e) => e,
                Err(e) => {
                    // Skip invalid events.
                    warn!(
                        error =? e,
                        "Received an invalid to-device event"
                    );
                    continue;
                }
            };

            info!(
                sender = event.sender().as_str(),
                event_type = event.event_type(),
                "Received a to-device event"
            );

            match event {
                AnyToDeviceEvent::RoomEncrypted(e) => {
                    let decrypted = match self.decrypt_to_device_event(&e).await {
                        Ok(e) => e,
                        Err(err) => {
                            warn!(sender = e.sender.as_str(), error =? e, "Failed to decrypt to-device event");

                            if let OlmError::SessionWedged(sender, curve_key) = err {
                                if let Err(e) = self
                                    .session_manager
                                    .mark_device_as_wedged(&sender, &curve_key)
                                    .await
                                {
                                    error!(
                                        sender = sender.as_str(),
                                        error =? e,
                                        "Couldn't mark device from to be unwedged",
                                    );
                                }
                            }
                            continue;
                        }
                    };

                    // New sessions modify the account so we need to save that
                    // one as well.
                    match decrypted.session {
                        SessionType::New(s) => {
                            changes.sessions.push(s);
                            changes.account = Some(self.account.inner.clone());
                        }
                        SessionType::Existing(s) => {
                            changes.sessions.push(s);
                        }
                    }

                    changes.message_hashes.push(decrypted.message_hash);

                    if let Some(group_session) = decrypted.inbound_group_session {
                        changes.inbound_group_sessions.push(group_session);
                    }

                    if let Some(event) = decrypted.deserialized_event {
                        self.handle_to_device_event(&event).await;
                    }

                    raw_event = decrypted.event;
                }
                e => self.handle_to_device_event(&e).await,
            }

            events.push(raw_event);
        }

        let changed_sessions = self.key_request_machine.collect_incoming_key_requests().await?;

        changes.sessions.extend(changed_sessions);

        self.store.save_changes(changes).await?;

        let mut to_device = ToDevice::new();
        to_device.events = events;

        Ok(to_device)
    }

    /// Request a room key from our devices.
    ///
    /// This method will return a request cancellation and a new key request if
    /// the key was already requested, otherwise it will return just the key
    /// request.
    ///
    /// The request cancellation *must* be sent out before the request is sent
    /// out, otherwise devices will ignore the key request.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The id of the room where the key is used in.
    ///
    /// * `sender_key` - The curve25519 key of the sender that owns the key.
    ///
    /// * `session_id` - The id that uniquely identifies the session.
    pub async fn request_room_key(
        &self,
        event: &SyncMessageEvent<EncryptedEventContent>,
        room_id: &RoomId,
    ) -> MegolmResult<(Option<OutgoingRequest>, OutgoingRequest)> {
        let content = match &event.content.scheme {
            EncryptedEventScheme::MegolmV1AesSha2(c) => c,
            _ => return Err(EventError::UnsupportedAlgorithm.into()),
        };

        Ok(self
            .key_request_machine
            .request_key(room_id, &content.sender_key, &content.session_id)
            .await?)
    }

    async fn get_encryption_info(
        &self,
        session: &InboundGroupSession,
        sender: &UserId,
        device_id: &DeviceId,
    ) -> StoreResult<EncryptionInfo> {
        let verification_state = if let Some(device) =
            self.get_device(sender, device_id).await?.filter(|d| {
                d.get_key(DeviceKeyAlgorithm::Curve25519)
                    .map(|k| k == session.sender_key())
                    .unwrap_or(false)
            }) {
            if (self.user_id() == device.user_id() && self.device_id() == device.device_id())
                || device.verified()
            {
                VerificationState::Trusted
            } else {
                VerificationState::Untrusted
            }
        } else {
            VerificationState::UnknownDevice
        };

        let sender = sender.clone();
        let device_id = device_id.to_owned();

        Ok(EncryptionInfo {
            sender,
            sender_device: device_id,
            algorithm_info: AlgorithmInfo::MegolmV1AesSha2 {
                curve25519_key: session.sender_key().to_owned(),
                sender_claimed_keys: session.signing_keys().to_owned(),
                forwarding_curve25519_key_chain: session.forwarding_key_chain().to_vec(),
            },
            verification_state,
        })
    }

    /// Decrypt an event from a room timeline.
    ///
    /// # Arguments
    ///
    /// * `event` - The event that should be decrypted.
    ///
    /// * `room_id` - The ID of the room where the event was sent to.
    pub async fn decrypt_room_event(
        &self,
        event: &SyncMessageEvent<EncryptedEventContent>,
        room_id: &RoomId,
    ) -> MegolmResult<SyncRoomEvent> {
        let content = match &event.content.scheme {
            EncryptedEventScheme::MegolmV1AesSha2(c) => c,
            _ => return Err(EventError::UnsupportedAlgorithm.into()),
        };

        let session = self
            .store
            .get_inbound_group_session(room_id, &content.sender_key, &content.session_id)
            .await?;
        // TODO check if the Olm session is wedged and re-request the key.
        let session = if let Some(s) = session {
            s
        } else {
            self.key_request_machine
                .create_outgoing_key_request(room_id, &content.sender_key, &content.session_id)
                .await?;
            return Err(MegolmError::MissingSession);
        };

        // TODO check the message index.
        // TODO check if this is from a verified device.
        let (decrypted_event, _) = session.decrypt(event).await?;

        trace!("Successfully decrypted a Megolm event {:?}", decrypted_event);

        if let Ok(e) = decrypted_event.deserialize() {
            let event = e.into_full_event(room_id.to_owned());

            if let AnyRoomEvent::Message(e) = event {
                self.verification_machine.receive_any_event(&e).await?;
            }
        }

        let encryption_info =
            self.get_encryption_info(&session, &event.sender, &content.device_id).await?;

        Ok(SyncRoomEvent { encryption_info: Some(encryption_info), event: decrypted_event })
    }

    /// Update the tracked users.
    ///
    /// # Arguments
    ///
    /// * `users` - An iterator over user ids that should be marked for
    /// tracking.
    ///
    /// This will mark users that weren't seen before for a key query and
    /// tracking.
    ///
    /// If the user is already known to the Olm machine it will not be
    /// considered for a key query.
    pub async fn update_tracked_users(&self, users: impl IntoIterator<Item = &UserId>) {
        self.identity_manager.update_tracked_users(users).await
    }

    /// Get a specific device of a user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique id of the user that the device belongs to.
    ///
    /// * `device_id` - The unique id of the device.
    ///
    /// Returns a `Device` if one is found and the crypto store didn't throw an
    /// error.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::convert::TryFrom;
    /// # use matrix_sdk_crypto::OlmMachine;
    /// # use ruma::UserId;
    /// # use futures::executor::block_on;
    /// # let alice = UserId::try_from("@alice:example.org").unwrap();
    /// # let machine = OlmMachine::new(&alice, "DEVICEID".into());
    /// # block_on(async {
    /// let device = machine.get_device(&alice, "DEVICEID".into()).await;
    ///
    /// println!("{:?}", device);
    /// # });
    /// ```
    pub async fn get_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> StoreResult<Option<Device>> {
        self.store.get_device(user_id, device_id).await
    }

    /// Get the cross signing user identity of a user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique id of the user that the identity belongs to
    ///
    /// Returns a `UserIdentities` enum if one is found and the crypto store
    /// didn't throw an error.
    pub async fn get_identity(&self, user_id: &UserId) -> StoreResult<Option<UserIdentities>> {
        self.store.get_identity(user_id).await
    }

    /// Get a map holding all the devices of an user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique id of the user that the devices belong to.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::convert::TryFrom;
    /// # use matrix_sdk_crypto::OlmMachine;
    /// # use ruma::UserId;
    /// # use futures::executor::block_on;
    /// # let alice = UserId::try_from("@alice:example.org").unwrap();
    /// # let machine = OlmMachine::new(&alice, "DEVICEID".into());
    /// # block_on(async {
    /// let devices = machine.get_user_devices(&alice).await.unwrap();
    ///
    /// for device in devices.devices() {
    ///     println!("{:?}", device);
    /// }
    /// # });
    /// ```
    pub async fn get_user_devices(&self, user_id: &UserId) -> StoreResult<UserDevices> {
        self.store.get_user_devices(user_id).await
    }

    /// Import the given room keys into our store.
    ///
    /// # Arguments
    ///
    /// * `exported_keys` - A list of previously exported keys that should be
    /// imported into our store. If we already have a better version of a key
    /// the key will *not* be imported.
    ///
    /// Returns a tuple of numbers that represent the number of sessions that
    /// were imported and the total number of sessions that were found in the
    /// key export.
    ///
    /// # Examples
    /// ```no_run
    /// # use std::io::Cursor;
    /// # use matrix_sdk_crypto::{OlmMachine, decrypt_key_export};
    /// # use ruma::user_id;
    /// # use futures::executor::block_on;
    /// # let alice = user_id!("@alice:example.org");
    /// # let machine = OlmMachine::new(&alice, "DEVICEID".into());
    /// # block_on(async {
    /// # let export = Cursor::new("".to_owned());
    /// let exported_keys = decrypt_key_export(export, "1234").unwrap();
    /// machine.import_keys(exported_keys, |_, _| {}).await.unwrap();
    /// # });
    /// ```
    pub async fn import_keys(
        &self,
        exported_keys: Vec<ExportedRoomKey>,
        progress_listener: impl Fn(usize, usize),
    ) -> StoreResult<(usize, usize)> {
        struct ShallowSessions {
            inner: BTreeMap<Arc<RoomId>, u32>,
        }

        impl ShallowSessions {
            fn has_better_session(&self, session: &InboundGroupSession) -> bool {
                self.inner
                    .get(&session.room_id)
                    .map(|existing| existing <= &session.first_known_index())
                    .unwrap_or(false)
            }
        }

        let mut sessions = Vec::new();

        let existing_sessions = ShallowSessions {
            inner: self
                .store
                .get_inbound_group_sessions()
                .await?
                .into_iter()
                .map(|s| {
                    let index = s.first_known_index();
                    (s.room_id, index)
                })
                .collect(),
        };

        let total_sessions = exported_keys.len();

        for (i, key) in exported_keys.into_iter().enumerate() {
            let session = InboundGroupSession::from_export(key)?;

            // Only import the session if we didn't have this session or if it's
            // a better version of the same session, that is the first known
            // index is lower.
            if !existing_sessions.has_better_session(&session) {
                sessions.push(session)
            }

            progress_listener(i, total_sessions)
        }

        let num_sessions = sessions.len();

        let changes = Changes { inbound_group_sessions: sessions, ..Default::default() };

        self.store.save_changes(changes).await?;

        info!("Successfully imported {} inbound group sessions", num_sessions);

        Ok((num_sessions, total_sessions))
    }

    /// Export the keys that match the given predicate.
    ///
    /// # Arguments
    ///
    /// * `predicate` - A closure that will be called for every known
    /// `InboundGroupSession`, which represents a room key. If the closure
    /// returns `true` the `InboundGroupSession` will be included in the export,
    /// if the closure returns `false` it will not be included.
    ///
    /// # Panics
    ///
    /// This method will panic if it can't get enough randomness from the OS to
    /// encrypt the exported keys securely.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matrix_sdk_crypto::{OlmMachine, encrypt_key_export};
    /// # use ruma::{user_id, room_id};
    /// # use futures::executor::block_on;
    /// # let alice = user_id!("@alice:example.org");
    /// # let machine = OlmMachine::new(&alice, "DEVICEID".into());
    /// # block_on(async {
    /// let room_id = room_id!("!test:localhost");
    /// let exported_keys = machine.export_keys(|s| s.room_id() == &room_id).await.unwrap();
    /// let encrypted_export = encrypt_key_export(&exported_keys, "1234", 1);
    /// # });
    /// ```
    pub async fn export_keys(
        &self,
        mut predicate: impl FnMut(&InboundGroupSession) -> bool,
    ) -> StoreResult<Vec<ExportedRoomKey>> {
        let mut exported = Vec::new();

        let mut sessions: Vec<InboundGroupSession> = self
            .store
            .get_inbound_group_sessions()
            .await?
            .drain(..)
            .filter(|s| predicate(s))
            .collect();

        for session in sessions.drain(..) {
            let export = session.export().await;
            exported.push(export);
        }

        Ok(exported)
    }

    /// Get the status of the private cross signing keys.
    ///
    /// This can be used to check which private cross signing keys we have
    /// stored locally.
    pub async fn cross_signing_status(&self) -> CrossSigningStatus {
        self.user_identity.lock().await.status().await
    }

    /// Export all the private cross signing keys we have.
    ///
    /// The export will contain the seed for the ed25519 keys as a unpadded
    /// base64 encoded string.
    ///
    /// This method returns `None` if we don't have any private cross signing
    /// keys.
    pub async fn export_cross_signing_keys(&self) -> Option<CrossSigningKeyExport> {
        let master_key = self.store.export_secret(&SecretName::CrossSigningMasterKey).await;
        let self_signing_key =
            self.store.export_secret(&SecretName::CrossSigningSelfSigningKey).await;
        let user_signing_key =
            self.store.export_secret(&SecretName::CrossSigningUserSigningKey).await;

        if master_key.is_none() && self_signing_key.is_none() && user_signing_key.is_none() {
            None
        } else {
            Some(CrossSigningKeyExport { master_key, self_signing_key, user_signing_key })
        }
    }

    /// Import our private cross signing keys.
    ///
    /// The export needs to contain the seed for the ed25519 keys as an unpadded
    /// base64 encoded string.
    pub async fn import_cross_signing_keys(
        &self,
        export: CrossSigningKeyExport,
    ) -> Result<CrossSigningStatus, SecretImportError> {
        self.store.import_cross_signing_keys(export).await
    }
}

#[cfg(test)]
pub(crate) mod test {
    static USER_ID: &str = "@bob:example.org";

    use std::{
        collections::BTreeMap,
        convert::{TryFrom, TryInto},
        sync::Arc,
    };

    use http::Response;
    use matrix_sdk_test::test_json;
    use ruma::{
        api::{
            client::r0::keys::{claim_keys, get_keys, upload_keys},
            IncomingResponse,
        },
        encryption::OneTimeKey,
        event_id,
        events::{
            dummy::DummyToDeviceEventContent,
            room::{
                encrypted::EncryptedToDeviceEventContent,
                message::{MessageEventContent, MessageType},
            },
            AnyMessageEventContent, AnySyncMessageEvent, AnySyncRoomEvent, AnyToDeviceEvent,
            AnyToDeviceEventContent, SyncMessageEvent, ToDeviceEvent, Unsigned,
        },
        room_id, uint, user_id, DeviceId, DeviceKeyAlgorithm, DeviceKeyId,
        MilliSecondsSinceUnixEpoch, UserId,
    };
    use serde_json::json;

    use crate::{
        machine::OlmMachine,
        olm::Utility,
        verification::test::{outgoing_request_to_event, request_to_event},
        EncryptionSettings, ReadOnlyDevice, ToDeviceRequest,
    };

    /// These keys need to be periodically uploaded to the server.
    type OneTimeKeys = BTreeMap<DeviceKeyId, OneTimeKey>;

    fn alice_id() -> UserId {
        user_id!("@alice:example.org")
    }

    fn alice_device_id() -> Box<DeviceId> {
        "JLAFKJWSCS".into()
    }

    fn user_id() -> UserId {
        UserId::try_from(USER_ID).unwrap()
    }

    pub fn response_from_file(json: &serde_json::Value) -> Response<Vec<u8>> {
        Response::builder().status(200).body(json.to_string().as_bytes().to_vec()).unwrap()
    }

    fn keys_upload_response() -> upload_keys::Response {
        let data = response_from_file(&test_json::KEYS_UPLOAD);
        upload_keys::Response::try_from_http_response(data)
            .expect("Can't parse the keys upload response")
    }

    fn keys_query_response() -> get_keys::Response {
        let data = response_from_file(&test_json::KEYS_QUERY);
        get_keys::Response::try_from_http_response(data)
            .expect("Can't parse the keys upload response")
    }

    fn to_device_requests_to_content(
        requests: Vec<Arc<ToDeviceRequest>>,
    ) -> EncryptedToDeviceEventContent {
        let to_device_request = &requests[0];

        to_device_request
            .messages
            .values()
            .next()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .deserialize_as()
            .unwrap()
    }

    pub(crate) async fn get_prepared_machine() -> (OlmMachine, OneTimeKeys) {
        let machine = OlmMachine::new(&user_id(), &alice_device_id());
        machine.account.inner.update_uploaded_key_count(0);
        let request = machine.keys_for_upload().await.expect("Can't prepare initial key upload");
        let response = keys_upload_response();
        machine.receive_keys_upload_response(&response).await.unwrap();

        (machine, request.one_time_keys.unwrap())
    }

    async fn get_machine_after_query() -> (OlmMachine, OneTimeKeys) {
        let (machine, otk) = get_prepared_machine().await;
        let response = keys_query_response();

        machine.receive_keys_query_response(&response).await.unwrap();

        (machine, otk)
    }

    async fn get_machine_pair() -> (OlmMachine, OlmMachine, OneTimeKeys) {
        let (bob, otk) = get_prepared_machine().await;

        let alice_id = alice_id();
        let alice_device = alice_device_id();
        let alice = OlmMachine::new(&alice_id, &alice_device);

        let alice_device = ReadOnlyDevice::from_machine(&alice).await;
        let bob_device = ReadOnlyDevice::from_machine(&bob).await;
        alice.store.save_devices(&[bob_device]).await.unwrap();
        bob.store.save_devices(&[alice_device]).await.unwrap();

        (alice, bob, otk)
    }

    async fn get_machine_pair_with_session() -> (OlmMachine, OlmMachine) {
        let (alice, bob, one_time_keys) = get_machine_pair().await;

        let mut bob_keys = BTreeMap::new();

        let one_time_key = one_time_keys.iter().next().unwrap();
        let mut keys = BTreeMap::new();
        keys.insert(one_time_key.0.clone(), one_time_key.1.clone());
        bob_keys.insert(bob.device_id().into(), keys);

        let mut one_time_keys = BTreeMap::new();
        one_time_keys.insert(bob.user_id().clone(), bob_keys);

        let response = claim_keys::Response::new(one_time_keys);

        alice.receive_keys_claim_response(&response).await.unwrap();

        (alice, bob)
    }

    async fn get_machine_pair_with_setup_sessions() -> (OlmMachine, OlmMachine) {
        let (alice, bob) = get_machine_pair_with_session().await;

        let bob_device = alice.get_device(&bob.user_id, &bob.device_id).await.unwrap().unwrap();

        let (session, content) = bob_device
            .encrypt(AnyToDeviceEventContent::Dummy(DummyToDeviceEventContent::new()))
            .await
            .unwrap();
        alice.store.save_sessions(&[session]).await.unwrap();

        let event = ToDeviceEvent { sender: alice.user_id().clone(), content };

        let decrypted = bob.decrypt_to_device_event(&event).await.unwrap();
        bob.store.save_sessions(&[decrypted.session.session()]).await.unwrap();

        (alice, bob)
    }

    #[tokio::test]
    async fn create_olm_machine() {
        let machine = OlmMachine::new(&user_id(), &alice_device_id());
        assert!(machine.should_upload_keys().await);
    }

    #[tokio::test]
    async fn receive_keys_upload_response() {
        let machine = OlmMachine::new(&user_id(), &alice_device_id());
        let mut response = keys_upload_response();

        response.one_time_key_counts.remove(&DeviceKeyAlgorithm::SignedCurve25519).unwrap();

        assert!(machine.should_upload_keys().await);
        machine.receive_keys_upload_response(&response).await.unwrap();
        assert!(machine.should_upload_keys().await);

        response.one_time_key_counts.insert(DeviceKeyAlgorithm::SignedCurve25519, uint!(10));
        machine.receive_keys_upload_response(&response).await.unwrap();
        assert!(machine.should_upload_keys().await);

        response.one_time_key_counts.insert(DeviceKeyAlgorithm::SignedCurve25519, uint!(50));
        machine.receive_keys_upload_response(&response).await.unwrap();
        assert!(!machine.should_upload_keys().await);

        response.one_time_key_counts.remove(&DeviceKeyAlgorithm::SignedCurve25519);
        machine.receive_keys_upload_response(&response).await.unwrap();
        assert!(!machine.should_upload_keys().await);
    }

    #[tokio::test]
    async fn generate_one_time_keys() {
        let machine = OlmMachine::new(&user_id(), &alice_device_id());

        let mut response = keys_upload_response();

        assert!(machine.should_upload_keys().await);

        machine.receive_keys_upload_response(&response).await.unwrap();
        assert!(machine.should_upload_keys().await);
        assert!(machine.account.generate_one_time_keys().await.is_ok());

        response.one_time_key_counts.insert(DeviceKeyAlgorithm::SignedCurve25519, uint!(50));
        machine.receive_keys_upload_response(&response).await.unwrap();
        assert!(machine.account.generate_one_time_keys().await.is_err());
    }

    #[tokio::test]
    async fn test_device_key_signing() {
        let machine = OlmMachine::new(&user_id(), &alice_device_id());

        let mut device_keys = machine.account.device_keys().await;
        let identity_keys = machine.account.identity_keys();
        let ed25519_key = identity_keys.ed25519();

        let utility = Utility::new();
        let ret = utility.verify_json(
            &machine.user_id,
            &DeviceKeyId::from_parts(DeviceKeyAlgorithm::Ed25519, machine.device_id()),
            ed25519_key,
            &mut json!(&mut device_keys),
        );
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn tests_session_invalidation() {
        let machine = OlmMachine::new(&user_id(), &alice_device_id());
        let room_id = room_id!("!test:example.org");

        machine.create_outbound_group_session_with_defaults(&room_id).await.unwrap();
        assert!(machine.group_session_manager.get_outbound_group_session(&room_id).is_some());

        machine.invalidate_group_session(&room_id).await.unwrap();

        assert!(machine
            .group_session_manager
            .get_outbound_group_session(&room_id)
            .unwrap()
            .invalidated());
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let machine = OlmMachine::new(&user_id(), &alice_device_id());

        let mut device_keys = machine.account.device_keys().await;

        let utility = Utility::new();
        let ret = utility.verify_json(
            &machine.user_id,
            &DeviceKeyId::from_parts(DeviceKeyAlgorithm::Ed25519, machine.device_id()),
            "fake_key",
            &mut json!(&mut device_keys),
        );
        assert!(ret.is_err());
    }

    #[tokio::test]
    async fn test_one_time_key_signing() {
        let machine = OlmMachine::new(&user_id(), &alice_device_id());
        machine.account.inner.update_uploaded_key_count(49);

        let mut one_time_keys = machine.account.signed_one_time_keys().await.unwrap();
        let identity_keys = machine.account.identity_keys();
        let ed25519_key = identity_keys.ed25519();

        let mut one_time_key = one_time_keys.values_mut().next().unwrap();

        let utility = Utility::new();
        let ret = utility.verify_json(
            &machine.user_id,
            &DeviceKeyId::from_parts(DeviceKeyAlgorithm::Ed25519, machine.device_id()),
            ed25519_key,
            &mut json!(&mut one_time_key),
        );
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_keys_for_upload() {
        let machine = OlmMachine::new(&user_id(), &alice_device_id());
        machine.account.inner.update_uploaded_key_count(0);

        let identity_keys = machine.account.identity_keys();
        let ed25519_key = identity_keys.ed25519();

        let mut request =
            machine.keys_for_upload().await.expect("Can't prepare initial key upload");

        let utility = Utility::new();
        let ret = utility.verify_json(
            &machine.user_id,
            &DeviceKeyId::from_parts(DeviceKeyAlgorithm::Ed25519, machine.device_id()),
            ed25519_key,
            &mut json!(&mut request.one_time_keys.as_mut().unwrap().values_mut().next()),
        );
        assert!(ret.is_ok());

        let utility = Utility::new();
        let ret = utility.verify_json(
            &machine.user_id,
            &DeviceKeyId::from_parts(DeviceKeyAlgorithm::Ed25519, machine.device_id()),
            ed25519_key,
            &mut json!(&mut request.device_keys.unwrap()),
        );
        assert!(ret.is_ok());

        let mut response = keys_upload_response();
        response.one_time_key_counts.insert(
            DeviceKeyAlgorithm::SignedCurve25519,
            (request.one_time_keys.unwrap().len() as u64).try_into().unwrap(),
        );

        machine.receive_keys_upload_response(&response).await.unwrap();

        let ret = machine.keys_for_upload().await;
        assert!(ret.is_none());
    }

    #[tokio::test]
    async fn test_keys_query() {
        let (machine, _) = get_prepared_machine().await;
        let response = keys_query_response();
        let alice_id = user_id!("@alice:example.org");
        let alice_device_id: &DeviceId = "JLAFKJWSCS".into();

        let alice_devices = machine.store.get_user_devices(&alice_id).await.unwrap();
        assert!(alice_devices.devices().peekable().peek().is_none());

        machine.receive_keys_query_response(&response).await.unwrap();

        let device = machine.store.get_device(&alice_id, alice_device_id).await.unwrap().unwrap();
        assert_eq!(device.user_id(), &alice_id);
        assert_eq!(device.device_id(), alice_device_id);
    }

    #[tokio::test]
    async fn test_missing_sessions_calculation() {
        let (machine, _) = get_machine_after_query().await;

        let alice = alice_id();
        let alice_device = alice_device_id();

        let (_, missing_sessions) =
            machine.get_missing_sessions(&mut [alice.clone()].iter()).await.unwrap().unwrap();

        assert!(missing_sessions.one_time_keys.contains_key(&alice));
        let user_sessions = missing_sessions.one_time_keys.get(&alice).unwrap();
        assert!(user_sessions.contains_key(&alice_device));
    }

    #[tokio::test]
    async fn test_session_creation() {
        let (alice_machine, bob_machine, one_time_keys) = get_machine_pair().await;

        let mut bob_keys = BTreeMap::new();

        let one_time_key = one_time_keys.iter().next().unwrap();
        let mut keys = BTreeMap::new();
        keys.insert(one_time_key.0.clone(), one_time_key.1.clone());
        bob_keys.insert(bob_machine.device_id().into(), keys);

        let mut one_time_keys = BTreeMap::new();
        one_time_keys.insert(bob_machine.user_id().clone(), bob_keys);

        let response = claim_keys::Response::new(one_time_keys);

        alice_machine.receive_keys_claim_response(&response).await.unwrap();

        let session = alice_machine
            .store
            .get_sessions(bob_machine.account.identity_keys().curve25519())
            .await
            .unwrap()
            .unwrap();

        assert!(!session.lock().await.is_empty())
    }

    #[tokio::test]
    async fn test_olm_encryption() {
        let (alice, bob) = get_machine_pair_with_session().await;

        let bob_device = alice.get_device(&bob.user_id, &bob.device_id).await.unwrap().unwrap();

        let event = ToDeviceEvent {
            sender: alice.user_id().clone(),
            content: bob_device
                .encrypt(AnyToDeviceEventContent::Dummy(DummyToDeviceEventContent::new()))
                .await
                .unwrap()
                .1,
        };

        let event = bob.decrypt_to_device_event(&event).await.unwrap().event.deserialize().unwrap();

        if let AnyToDeviceEvent::Dummy(e) = event {
            assert_eq!(&e.sender, alice.user_id());
        } else {
            panic!("Wrong event type found {:?}", event);
        }
    }

    #[tokio::test]
    async fn test_room_key_sharing() {
        let (alice, bob) = get_machine_pair_with_session().await;

        let room_id = room_id!("!test:example.org");

        let to_device_requests = alice
            .share_group_session(
                &room_id,
                [bob.user_id().clone()].iter(),
                EncryptionSettings::default(),
            )
            .await
            .unwrap();

        let event = ToDeviceEvent {
            sender: alice.user_id().clone(),
            content: to_device_requests_to_content(to_device_requests),
        };

        let alice_session =
            alice.group_session_manager.get_outbound_group_session(&room_id).unwrap();

        let decrypted = bob.decrypt_to_device_event(&event).await.unwrap();

        bob.store.save_sessions(&[decrypted.session.session()]).await.unwrap();
        bob.store
            .save_inbound_group_sessions(&[decrypted.inbound_group_session.unwrap()])
            .await
            .unwrap();
        let event = decrypted.deserialized_event.unwrap();

        if let AnyToDeviceEvent::RoomKey(event) = event {
            assert_eq!(&event.sender, alice.user_id());
            assert!(event.content.session_key.is_empty());
        } else {
            panic!("expected RoomKeyEvent found {:?}", event);
        }

        let session = bob
            .store
            .get_inbound_group_session(
                &room_id,
                alice.account.identity_keys().curve25519(),
                alice_session.session_id(),
            )
            .await;

        assert!(session.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_megolm_encryption() {
        let (alice, bob) = get_machine_pair_with_setup_sessions().await;
        let room_id = room_id!("!test:example.org");

        let to_device_requests = alice
            .share_group_session(
                &room_id,
                [bob.user_id().clone()].iter(),
                EncryptionSettings::default(),
            )
            .await
            .unwrap();

        let event = ToDeviceEvent {
            sender: alice.user_id().clone(),
            content: to_device_requests_to_content(to_device_requests),
        };

        let group_session =
            bob.decrypt_to_device_event(&event).await.unwrap().inbound_group_session;
        bob.store.save_inbound_group_sessions(&[group_session.unwrap()]).await.unwrap();

        let plaintext = "It is a secret to everybody";

        let content = MessageEventContent::text_plain(plaintext);

        let encrypted_content = alice
            .encrypt(&room_id, AnyMessageEventContent::RoomMessage(content.clone()))
            .await
            .unwrap();

        let event = SyncMessageEvent {
            event_id: event_id!("$xxxxx:example.org"),
            origin_server_ts: MilliSecondsSinceUnixEpoch::now(),
            sender: alice.user_id().clone(),
            content: encrypted_content,
            unsigned: Unsigned::default(),
        };

        let decrypted_event =
            bob.decrypt_room_event(&event, &room_id).await.unwrap().event.deserialize().unwrap();

        if let AnySyncRoomEvent::Message(AnySyncMessageEvent::RoomMessage(SyncMessageEvent {
            sender,
            content,
            ..
        })) = decrypted_event
        {
            assert_eq!(&sender, alice.user_id());
            if let MessageType::Text(c) = &content.msgtype {
                assert_eq!(&c.body, plaintext);
            } else {
                panic!("Decrypted event has a mismatched content");
            }
        } else {
            panic!("Decrypted room event has the wrong type")
        }
    }

    #[tokio::test]
    #[cfg(feature = "sled_cryptostore")]
    async fn test_machine_with_default_store() {
        use tempfile::tempdir;

        let tmpdir = tempdir().unwrap();

        let machine = OlmMachine::new_with_default_store(
            &user_id(),
            &alice_device_id(),
            tmpdir.as_ref(),
            Some("test"),
        )
        .await
        .unwrap();

        let user_id = machine.user_id().to_owned();
        let device_id = machine.device_id().to_owned();
        let ed25519_key = machine.identity_keys().ed25519().to_owned();

        machine.receive_keys_upload_response(&keys_upload_response()).await.unwrap();

        drop(machine);

        let machine = OlmMachine::new_with_default_store(
            &user_id,
            &alice_device_id(),
            tmpdir.as_ref(),
            Some("test"),
        )
        .await
        .unwrap();

        assert_eq!(&user_id, machine.user_id());
        assert_eq!(&*device_id, machine.device_id());
        assert_eq!(ed25519_key, machine.identity_keys().ed25519());
    }

    #[tokio::test]
    async fn interactive_verification() {
        let (alice, bob) = get_machine_pair_with_setup_sessions().await;

        let bob_device = alice.get_device(bob.user_id(), bob.device_id()).await.unwrap().unwrap();

        assert!(!bob_device.verified());

        let (alice_sas, request) = bob_device.start_verification().await.unwrap();

        let event = request_to_event(alice.user_id(), &request.into());
        bob.handle_verification_event(&event).await;

        let bob_sas = bob
            .get_verification(alice.user_id(), alice_sas.flow_id().as_str())
            .unwrap()
            .sas_v1()
            .unwrap();

        assert!(alice_sas.emoji().is_none());
        assert!(bob_sas.emoji().is_none());

        let event = bob_sas.accept().map(|r| request_to_event(bob.user_id(), &r)).unwrap();

        alice.handle_verification_event(&event).await;

        let event = alice
            .verification_machine
            .outgoing_messages()
            .first()
            .map(|r| outgoing_request_to_event(alice.user_id(), r))
            .unwrap();
        bob.handle_verification_event(&event).await;

        let event = bob
            .verification_machine
            .outgoing_messages()
            .first()
            .map(|r| outgoing_request_to_event(bob.user_id(), r))
            .unwrap();
        alice.handle_verification_event(&event).await;

        assert!(alice_sas.emoji().is_some());
        assert!(bob_sas.emoji().is_some());

        assert_eq!(alice_sas.emoji(), bob_sas.emoji());
        assert_eq!(alice_sas.decimals(), bob_sas.decimals());

        let event = bob_sas
            .confirm()
            .await
            .unwrap()
            .0
            .map(|r| request_to_event(bob.user_id(), &r))
            .unwrap();
        alice.handle_verification_event(&event).await;

        assert!(!alice_sas.is_done());
        assert!(!bob_sas.is_done());

        let event = alice_sas
            .confirm()
            .await
            .unwrap()
            .0
            .map(|r| request_to_event(alice.user_id(), &r))
            .unwrap();

        assert!(alice_sas.is_done());
        assert!(bob_device.verified());

        let alice_device =
            bob.get_device(alice.user_id(), alice.device_id()).await.unwrap().unwrap();

        assert!(!alice_device.verified());
        bob.handle_verification_event(&event).await;
        assert!(bob_sas.is_done());
        assert!(alice_device.verified());
    }
}
