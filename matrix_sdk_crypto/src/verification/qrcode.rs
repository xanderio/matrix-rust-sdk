// Copyright 2021 The Matrix.org Foundation C.I.C.
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

#![allow(dead_code)]
#![allow(missing_docs)]

use std::sync::{Arc, Mutex};

use matrix_qrcode::{
    qrcode::QrCode, EncodingError, QrVerification as InnerVerification, SelfVerificationData,
    SelfVerificationNoMasterKey, VerificationData,
};
use matrix_sdk_common::events::{
    key::verification::{
        cancel::CancelCode,
        done::{DoneEventContent, DoneToDeviceEventContent},
        start, Relation,
    },
    AnyMessageEventContent, AnyToDeviceEventContent,
};

use super::{
    requests::{DoneContent, StartContent},
    sas::OutgoingContent,
    Cancelled, FlowId,
};
use crate::{olm::ReadOnlyAccount, store::CryptoStore};

const SECRET_SIZE: usize = 16;

#[derive(Clone)]
pub struct QrVerification {
    flow_id: FlowId,
    store: Arc<Box<dyn CryptoStore>>,
    inner: Arc<InnerVerification>,
    state: Arc<Mutex<InnerState>>,
}

impl std::fmt::Debug for QrVerification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QrVerification")
            .field("flow_id", &self.flow_id)
            .field("inner", self.inner.as_ref())
            .field("state", &self.state.lock().unwrap())
            .finish()
    }
}

impl QrVerification {
    pub fn is_scanned(&self) -> bool {
        matches!(&*self.state.lock().unwrap(), InnerState::Scanned(_))
    }

    pub fn confirm_scanning(&self) -> Option<OutgoingContent> {
        let mut state = self.state.lock().unwrap();

        match &*state {
            InnerState::Scanned(s) => {
                let new_state = s.clone().confirm_scanning();
                let content = new_state.as_content(&self.flow_id);
                *state = InnerState::Confirmed(new_state);

                Some(content)
            }
            InnerState::Created(_)
            | InnerState::Done(_)
            | InnerState::Cancelled(_)
            | InnerState::Confirmed(_) => None,
        }
    }

    pub fn cancel(&self) -> Option<OutgoingContent> {
        let new_state = QrState::<Cancelled>::new(CancelCode::User);
        let content = new_state.as_content(self.flow_id());

        let mut state = self.state.lock().unwrap();

        match &*state {
            InnerState::Confirmed(_)
            | InnerState::Created(_)
            | InnerState::Scanned(_)
            | InnerState::Done(_) => {
                *state = InnerState::Cancelled(new_state);
                Some(content.into())
            }
            InnerState::Cancelled(_) => None,
        }
    }

    pub(crate) fn receive_done(&self, content: DoneContent) -> Option<OutgoingContent> {
        let mut state = self.state.lock().unwrap();

        match &*state {
            InnerState::Confirmed(c) => {
                let new_state = c.clone().into_done(content);
                *state = InnerState::Done(new_state);
                None
            }
            InnerState::Created(_)
            | InnerState::Scanned(_)
            | InnerState::Done(_)
            | InnerState::Cancelled(_) => None,
        }
    }

    pub(crate) fn receive_reciprocation(&self, content: StartContent) -> Option<OutgoingContent> {
        let mut state = self.state.lock().unwrap();

        match &*state {
            InnerState::Created(s) => match s.clone().receive_reciprocate(content) {
                Ok(s) => {
                    *state = InnerState::Scanned(s);
                    None
                }
                Err(s) => {
                    let content = s.as_content(self.flow_id());
                    *state = InnerState::Cancelled(s);
                    Some(content)
                }
            },
            InnerState::Confirmed(_)
            | InnerState::Scanned(_)
            | InnerState::Done(_)
            | InnerState::Cancelled(_) => None,
        }
    }

    fn generate_secret() -> String {
        let mut shared_secret = [0u8; SECRET_SIZE];
        getrandom::getrandom(&mut shared_secret)
            .expect("Can't generate randomness for the shared secret");
        crate::utilities::encode(shared_secret)
    }

    pub(crate) fn new_self(
        store: Arc<Box<dyn CryptoStore>>,
        flow_id: FlowId,
        own_master_key: String,
        other_device_key: String,
    ) -> Self {
        let secret = Self::generate_secret();

        let inner: InnerVerification = SelfVerificationData::new(
            flow_id.as_str().to_owned(),
            own_master_key,
            other_device_key,
            secret.clone(),
        )
        .into();

        Self::new_helper(store, flow_id, inner)
    }

    pub(crate) fn new_self_no_master(
        account: ReadOnlyAccount,
        store: Arc<Box<dyn CryptoStore>>,
        flow_id: FlowId,
        own_master_key: String,
    ) -> QrVerification {
        let secret = Self::generate_secret();

        let inner: InnerVerification = SelfVerificationNoMasterKey::new(
            flow_id.as_str().to_owned(),
            account.identity_keys().ed25519().to_string(),
            own_master_key,
            secret.clone(),
        )
        .into();

        Self::new_helper(store, flow_id, inner)
    }

    pub(crate) fn new(
        store: Arc<Box<dyn CryptoStore>>,
        flow_id: FlowId,
        own_master_key: String,
        other_master_key: String,
    ) -> Self {
        let secret = Self::generate_secret();

        let event_id = if let FlowId::InRoom(_, e) = &flow_id {
            e.to_owned()
        } else {
            panic!("A verification between users is only valid in a room");
        };

        let inner: InnerVerification =
            VerificationData::new(event_id, own_master_key, other_master_key, secret.clone())
                .into();

        Self::new_helper(store, flow_id, inner)
    }

    fn new_helper(
        store: Arc<Box<dyn CryptoStore>>,
        flow_id: FlowId,
        inner: InnerVerification,
    ) -> Self {
        let secret = inner.secret().to_owned();

        Self {
            store,
            flow_id,
            inner: inner.into(),
            state: Mutex::new(InnerState::Created(QrState { state: Created { secret } })).into(),
        }
    }

    pub fn flow_id(&self) -> &FlowId {
        &self.flow_id
    }

    pub fn secret(&self) -> &str {
        self.inner.secret()
    }

    pub fn to_qr_code(&self) -> Result<QrCode, EncodingError> {
        self.inner.to_qr_code()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodingError> {
        self.inner.to_bytes()
    }
}

#[derive(Debug)]
enum InnerState {
    Created(QrState<Created>),
    Scanned(QrState<Scanned>),
    Confirmed(QrState<Confirmed>),
    Done(QrState<Done>),
    Cancelled(QrState<Cancelled>),
}

#[derive(Clone, Debug)]
struct QrState<S: Clone> {
    state: S,
}

#[derive(Clone, Debug)]
struct Created {
    secret: String,
}

#[derive(Clone, Debug)]
struct Scanned {}

#[derive(Clone, Debug)]
struct Confirmed {}

#[derive(Clone, Debug)]
struct Done {}

impl QrState<Scanned> {
    fn confirm_scanning(self) -> QrState<Confirmed> {
        QrState { state: Confirmed {} }
    }
}

impl QrState<Cancelled> {
    fn new(cancel_code: CancelCode) -> Self {
        QrState { state: Cancelled::new(cancel_code) }
    }

    fn as_content(&self, flow_id: &FlowId) -> OutgoingContent {
        self.state.as_content(flow_id).into()
    }
}

impl QrState<Created> {
    fn receive_reciprocate(
        self,
        content: StartContent,
    ) -> Result<QrState<Scanned>, QrState<Cancelled>> {
        match content.method() {
            start::StartMethod::ReciprocateV1(m) => {
                // TODO use constant time eq here.
                if self.state.secret == m.secret {
                    Ok(QrState { state: Scanned {} })
                } else {
                    Err(QrState::<Cancelled>::new(CancelCode::KeyMismatch))
                }
            }
            _ => Err(QrState::<Cancelled>::new(CancelCode::UnknownMethod)),
        }
    }
}

impl QrState<Done> {
    fn as_content(&self, flow_id: &FlowId) -> OutgoingContent {
        match flow_id {
            FlowId::ToDevice(t) => AnyToDeviceEventContent::KeyVerificationDone(
                DoneToDeviceEventContent::new(t.to_owned()),
            )
            .into(),
            FlowId::InRoom(r, e) => (
                r.to_owned(),
                AnyMessageEventContent::KeyVerificationDone(DoneEventContent::new(Relation::new(
                    e.to_owned(),
                ))),
            )
                .into(),
        }
    }
}

impl QrState<Confirmed> {
    fn into_done(self, _: DoneContent) -> QrState<Done> {
        QrState { state: Done {} }
    }

    fn as_content(&self, flow_id: &FlowId) -> OutgoingContent {
        match flow_id {
            FlowId::ToDevice(t) => AnyToDeviceEventContent::KeyVerificationDone(
                DoneToDeviceEventContent::new(t.to_owned()),
            )
            .into(),
            FlowId::InRoom(r, e) => (
                r.to_owned(),
                AnyMessageEventContent::KeyVerificationDone(DoneEventContent::new(Relation::new(
                    e.to_owned(),
                ))),
            )
                .into(),
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use matrix_sdk_common::{
        events::key::verification::{
            start::{
                ReciprocateV1Content, StartEventContent, StartMethod, StartToDeviceEventContent,
            },
            Relation,
        },
        identifiers::{event_id, room_id, user_id, DeviceIdBox, UserId},
    };
    use matrix_sdk_test::async_test;

    use super::QrVerification;
    use crate::{
        olm::{PrivateCrossSigningIdentity, ReadOnlyAccount},
        store::{CryptoStore, MemoryStore},
        verification::FlowId,
    };

    fn user_id() -> UserId {
        user_id!("@example:localhost")
    }

    fn memory_store() -> Arc<Box<dyn CryptoStore>> {
        Arc::new(Box::new(MemoryStore::new()))
    }

    fn device_id() -> DeviceIdBox {
        "DEVICEID".into()
    }

    fn alice_device_id() -> DeviceIdBox {
        "ALICEDEVICE".into()
    }

    fn reciprocate_event(
        sender_device: DeviceIdBox,
        flow_id: FlowId,
        secret: String,
    ) -> StartContent {
        let method = StartMethod::ReciprocateV1(ReciprocateV1Content::new(secret));

        match flow_id {
            FlowId::ToDevice(t) => StartToDeviceEventContent::new(sender_device, t, method).into(),
            FlowId::InRoom(r, e) => {
                (r, StartEventContent::new(sender_device, method, Relation::new(e))).into()
            }
        }
    }

    // #[async_test]
    // async fn test_verification_creation() {
    //     let store = memory_store();

    //     let account = ReadOnlyAccount::new(&user_id(), &device_id());
    //     let private_identity =
    // PrivateCrossSigningIdentity::new(user_id()).await;     let flow_id =
    // FlowId::ToDevice("test_transaction".to_owned());

    //     let device_key = account.identity_keys().curve25519().to_owned();
    //     let master_key = private_identity.master_public_key().await.unwrap();
    //     let master_key = master_key.get_first_key().unwrap().to_owned();

    //     let verification = QrVerification::new_self_no_master(
    //         store.clone(),
    //         flow_id.clone(),
    //         device_key.clone(),
    //         master_key.clone(),
    //     );

    //     assert_eq!(verification.inner.first_key(), &device_key);
    //     assert_eq!(verification.inner.second_key(), &master_key);

    //     let verification = QrVerification::new_self(
    //         store.clone(),
    //         flow_id,
    //         master_key.clone(),
    //         device_key.clone(),
    //     );

    //     assert_eq!(verification.inner.first_key(), &master_key);
    //     assert_eq!(verification.inner.second_key(), &device_key);

    //     let bob_identity =
    // PrivateCrossSigningIdentity::new(user_id!("@bob:example")).await;
    //     let bob_master_key = bob_identity.master_public_key().await.unwrap();
    //     let bob_master_key =
    // bob_master_key.get_first_key().unwrap().to_owned();

    //     let flow_id = FlowId::InRoom(room_id!("!test:example"),
    // event_id!("$EVENTID"));

    //     let verification =
    //         QrVerification::new(store.clone(), flow_id, master_key.clone(),
    // bob_master_key.clone());

    //     assert_eq!(verification.inner.first_key(), &master_key);
    //     assert_eq!(verification.inner.second_key(), &bob_master_key);
    // }

    // #[async_test]
    // async fn test_reciprocate_receival() {
    //     let store = memory_store();

    //     let account = ReadOnlyAccount::new(&user_id(), &device_id());
    //     let private_identity =
    // PrivateCrossSigningIdentity::new(user_id()).await;     let flow_id =
    // FlowId::ToDevice("test_transaction".to_owned());

    //     let device_key = account.identity_keys().curve25519().to_owned();
    //     let master_key = private_identity.master_public_key().await.unwrap();
    //     let master_key = master_key.get_first_key().unwrap().to_owned();

    //     let verification = QrVerification::new_self_no_master(
    //         store,
    //         flow_id.clone(),
    //         device_key.clone(),
    //         master_key.clone(),
    //     );

    //     let content = reciprocate_event(
    //         alice_device_id(),
    //         verification.flow_id().to_owned(),
    //         verification.secret().to_owned(),
    //     );

    //     verification.receive_reciprocation(content);
    // }
}
