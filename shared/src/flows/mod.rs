use rand::RngCore;
use rsa::{pkcs1::EncodeRsaPrivateKey, RsaPrivateKey, RsaPublicKey};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::crypto::{self, aes256_gcm_encrypt, compute_srp_verifier};
use crate::derivation;
use crate::primitives::{
    AccountUnlockKey, AutoZeroedByteArray, NormalizedEmail, NormalizedPassword, Salt, SecretKey,
    SecureRemotePasswordSecret, SrpVerifier, Pbkdf2Params, Aes256GcmEncryptedDataB64, Aes256GcmEncryptedData,
};

pub struct RegistrationInfo {
    pub secret: SecretKey,
    pub encryption_key_salt: Salt,
    pub auk: AccountUnlockKey,
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
    pub encrypted_private_key: Aes256GcmEncryptedData,
    pub key_set_id: Uuid,
    pub device_id: Uuid,
    pub authentication_salt: Salt,
    pub srp: SecureRemotePasswordSecret,
    pub srp_verifier: SrpVerifier,
}

pub fn generate_registration_info(password: &str, email: &str, account_id: &str) -> RegistrationInfo {
    let password = NormalizedPassword::new(password.to_owned());
    let email = NormalizedEmail::new(email.to_owned());

    let secret = SecretKey::generate_random(account_id);

    let mut rng = rand::thread_rng();
    let mut encryption_key_salt = [0u8; 16];
    rng.fill_bytes(&mut encryption_key_salt);
    let encryption_key_salt = Salt(AutoZeroedByteArray::new(encryption_key_salt.to_vec()));

    let auk =
        AccountUnlockKey::from_user_info(&password, &secret, &encryption_key_salt, &email, &account_id);

    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    let private_encoded = private_key.to_pkcs1_der().unwrap();

    let encrypted_private_key = aes256_gcm_encrypt(
        private_encoded.as_bytes(),
        auk.0.as_slice(),
        &vec!['A' as u8, '3' as u8],
    );

    let key_set_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    let mut authentication_salt = [0u8; 16];
    rng.fill_bytes(&mut authentication_salt);
    let authentication_salt = Salt(AutoZeroedByteArray::new(authentication_salt.to_vec()));

    let srp = SecureRemotePasswordSecret::from_user_info(
        &password,
        &secret,
        &authentication_salt,
        &email,
        account_id,
    );

    let srp_verifier = compute_srp_verifier(&srp);

    RegistrationInfo {
        secret,
        encryption_key_salt,
        auk,
        private_key,
        public_key,
        encrypted_private_key,
        key_set_id,
        device_id,
        authentication_salt,
        srp,
        srp_verifier
    }
}

#[derive(Serialize, Deserialize)]
pub struct RegistrationInitiationRequest {
    pub email: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegistrationCompletionRequest {
    pub invite_id: Uuid,
    pub acceptance_token: String,
    pub auk_params: Pbkdf2Params,
    pub srp_verifier: String,
    pub srp_params: Pbkdf2Params,
    pub public_key: String,
    pub enc_priv_key: Aes256GcmEncryptedDataB64,
    pub enc_vault_details: Aes256GcmEncryptedDataB64,
    pub enc_vault_overview: Aes256GcmEncryptedDataB64,
    pub enc_vault_key: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginHandshakeStart {
    pub a_pub: String,
    pub email: String,
    pub account_id: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginHandshakeStartResponse {
    pub handshake_id: uuid::Uuid,
    pub b_pub: String
}

pub type LoginHandshakeConfirmationValue = Aes256GcmEncryptedDataB64;

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginHandshakeConfirmation {
    pub handshake_id: uuid::Uuid,
    pub confirmation: LoginHandshakeConfirmationValue
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginHandshakeConfirmationResponse {
    pub session_id: uuid::Uuid
}