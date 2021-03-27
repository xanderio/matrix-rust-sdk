use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    chain_key::{ChainKey, RemoteChainKey},
    root_key::{RemoteRootKey, RootKey},
};

pub(crate) struct Shared3DHSecret([u8; 96]);
pub(crate) struct RemoteShared3DHSecret([u8; 96]);

fn expand(shared_secret: [u8; 96]) -> ([u8; 32], [u8; 32]) {
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), &shared_secret);
    let mut root_key = [0u8; 32];
    let mut chain_key = [0u8; 32];

    // TODO zeroize this.
    let mut expanded_keys = [0u8; 64];

    hkdf.expand(b"OLM_ROOT", &mut expanded_keys).unwrap();

    root_key.copy_from_slice(&expanded_keys[0..32]);
    chain_key.copy_from_slice(&expanded_keys[32..64]);

    (root_key, chain_key)
}

impl RemoteShared3DHSecret {
    pub fn new(
        identity_key: &StaticSecret,
        one_time_key: &StaticSecret,
        remote_identity_key: &PublicKey,
        remote_one_time_key: &PublicKey,
    ) -> Self {
        let first_secret = one_time_key.diffie_hellman(&remote_identity_key);
        let second_secret = identity_key.diffie_hellman(&remote_one_time_key);
        let third_secret = one_time_key.diffie_hellman(&remote_one_time_key);

        let mut secret = Self([0u8; 96]);

        secret.0[0..32].copy_from_slice(first_secret.as_bytes());
        secret.0[32..64].copy_from_slice(second_secret.as_bytes());
        secret.0[64..96].copy_from_slice(third_secret.as_bytes());

        secret
    }

    pub(super) fn expand(self) -> (RemoteRootKey, RemoteChainKey) {
        let (root_key, chain_key) = expand(self.0);
        let root_key = RemoteRootKey::new(root_key);
        let chain_key = RemoteChainKey::new(chain_key);

        (root_key, chain_key)
    }
}

impl Shared3DHSecret {
    pub fn new(
        identity_key: &StaticSecret,
        one_time_key: &StaticSecret,
        remote_identity_key: &PublicKey,
        remote_one_time_key: &PublicKey,
    ) -> Self {
        let first_secret = identity_key.diffie_hellman(remote_one_time_key);
        let second_secret = one_time_key.diffie_hellman(remote_identity_key);
        let third_secret = one_time_key.diffie_hellman(remote_one_time_key);

        let mut secret = Self([0u8; 96]);

        secret.0[0..32].copy_from_slice(first_secret.as_bytes());
        secret.0[32..64].copy_from_slice(second_secret.as_bytes());
        secret.0[64..96].copy_from_slice(third_secret.as_bytes());

        secret
    }

    pub(super) fn expand(self) -> (RootKey, ChainKey) {
        let (root_key, chain_key) = expand(self.0);

        let root_key = RootKey::new(root_key);
        let chain_key = ChainKey::new(chain_key);

        (root_key, chain_key)
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{RemoteShared3DHSecret, Shared3DHSecret};

    #[test]
    fn tripple_diffie_hellman() {
        let mut rng = thread_rng();

        let alice_identity = StaticSecret::new(&mut rng);
        let alice_one_time = StaticSecret::new(&mut rng);

        let bob_identity = StaticSecret::new(&mut rng);
        let bob_one_time = StaticSecret::new(&mut rng);

        let alice_secret = Shared3DHSecret::new(
            &alice_identity,
            &alice_one_time,
            &PublicKey::from(&bob_identity),
            &PublicKey::from(&bob_one_time),
        );

        let bob_secret = RemoteShared3DHSecret::new(
            &bob_identity,
            &bob_one_time,
            &PublicKey::from(&alice_identity),
            &PublicKey::from(&alice_one_time),
        );

        assert_eq!(alice_secret.0, bob_secret.0);

        let (alice_root, _) = alice_secret.expand();
        let (bob_root, _) = bob_secret.expand();

        assert_eq!(alice_root.0, bob_root.0);
    }
}
