use crate::primitives::{
    self, AccountUnlockKey, AutoZeroedByteArray, NormalizedEmail, NormalizedPassword, Salt,
    SecretKey, SecureRemotePasswordSecret,
};
use hkdf::{self, Hkdf};
use pbkdf2::{self, pbkdf2_hmac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use serde_json::{json};
use base64::{engine::general_purpose as b64, Engine};

impl Salt {
    fn generate() -> Salt {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Salt(AutoZeroedByteArray::new(salt.to_vec()))
    }
}

fn derive_key(
    password: &NormalizedPassword,
    secret: &SecretKey,
    salt: &Salt,
    email: &NormalizedEmail,
    account_id: &str,
) -> AutoZeroedByteArray {
    let s_hkdf = Hkdf::<Sha256>::new(Some(salt.0.as_slice()), email.0.as_bytes());
    let mut s = [0u8; 32];
    s_hkdf.expand(&vec!['A' as u8, '3' as u8], &mut s).unwrap();

    let mut km = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.0.as_slice(), salt.0.as_slice(), 650_000, &mut km);

    let ka_hkdf = Hkdf::<Sha256>::new(Some(secret.0.as_slice()), &account_id.as_bytes());
    let mut ka = [0u8; 32];
    ka_hkdf
        .expand(&vec!['A' as u8, '3' as u8], &mut ka)
        .unwrap();

    let key: Vec<u8> = (0..32).map(|i| km[i] ^ ka[i]).collect();
    AutoZeroedByteArray::new(key)
}

impl AccountUnlockKey {
    pub fn from_user_info(
        password: &NormalizedPassword,
        secret: &SecretKey,
        salt: &Salt,
        email: &NormalizedEmail,
        account_id: &str,
    ) -> AccountUnlockKey {
        let key = derive_key(password, secret, salt, email, account_id);
        AccountUnlockKey(key)
    }

    pub fn to_jwk(&self) -> String {
        let encoded = b64::STANDARD.encode(self.0.as_slice());
        json!({
            "alg": "A256GCM",
            "ext": false,
            "k": encoded,
            "key_ops": ["encrypt","decrypt"],
            "kty": "oct",
            "kid": "mp"
        }).to_string()
    }
}

impl SecureRemotePasswordSecret {
    pub fn from_user_info(
        password: &NormalizedPassword,
        secret: &SecretKey,
        salt: &Salt,
        email: &NormalizedEmail,
        account_id: &str,
    ) -> SecureRemotePasswordSecret {
        let key = derive_key(password, secret, salt, email, account_id);
        SecureRemotePasswordSecret(key)
    }
}
