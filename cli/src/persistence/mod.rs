use std::{
    fs::File,
    io::{self, Write},
    str,
};

use anyhow::{anyhow, Result};
use pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use shared::{
    crypto,
    primitives::{
        Aes256GcmEncryptedData, Aes256GcmEncryptedDataB64, NormalizedPassword, Pbkdf2Params,
        SecretKey,
    },
    utils::{b64_url_decode, b64_url_encode},
};
use shared::{
    crypto::aes256_gcm_decrypt,
    primitives::Salt,
    rsa::{RsaPrivateKey, RsaPublicKey},
};
use shared::{
    crypto::aes256_gcm_encrypt,
    primitives::{
        AccountUnlockKey, AutoZeroedByteArray, NormalizedEmail, SecureRemotePasswordSecret,
    },
};
use substring::Substring;

#[derive(Serialize, Deserialize)]
pub struct SerializedUserData {
    pub email: String,
    pub account_string: String,
    pub auk_gen_params: Pbkdf2Params,
    pub srp_gen_params: Pbkdf2Params,
    pub enc_srp: Aes256GcmEncryptedDataB64,
    pub pub_key: String,
    pub enc_priv_key: Aes256GcmEncryptedDataB64,
}

pub struct UserData {
    pub email: String,
    pub secret_key: SecretKey,
    pub account_id: String,
    pub auk: AccountUnlockKey,
    pub auk_salt: Salt,
    pub srpx: SecureRemotePasswordSecret,
    pub srp_salt: Salt,
    pub pub_key: RsaPublicKey,
    pub priv_key: RsaPrivateKey,
}

fn persist_serialized_user_data(sud: &SerializedUserData) -> Result<()> {
    let email = NormalizedEmail::new(sud.email.clone());

    let json = json!(sud).to_string();

    let home = home::home_dir().unwrap();
    let path = home
        .join(".kelkaj-pasvortoj")
        .join(format!("{}.json", email.0));

    let mut file = match File::create(&path) {
        Err(why) => return Err(anyhow!("couldn't create {}: {}", path.display(), why)),
        Ok(file) => file,
    };

    match file.write_all(json.as_bytes()) {
        Err(why) => Err(anyhow!("couldn't write to {}: {}", path.display(), why)),
        Ok(_) => Ok(()),
    }
}

pub fn save_user_data(ud: &UserData) -> Result<()> {
    let email = ud.email.clone();
    let account_string =
        "A3".to_owned() + &ud.account_id + str::from_utf8(ud.secret_key.0.as_slice()).unwrap();

    let auk_gen_params = Pbkdf2Params {
        algo: "PBKDF2-HMAC-SHA256".to_string(),
        salt: ud.auk_salt.0.to_b64(),
        iterations: 650_000,
    };

    let srp_gen_params = Pbkdf2Params {
        algo: "PBKDF2-HMAC-SHA256".to_string(),
        salt: ud.srp_salt.0.to_b64(),
        iterations: 650_000,
    };

    let enc_srp = aes256_gcm_encrypt(
        ud.srpx.0.as_slice(),
        ud.auk.0.as_slice(),
        &['A' as u8, '3' as u8],
    );

    let enc_srp = enc_srp.to_b64();

    let pub_key = ud.pub_key.to_pkcs1_der().unwrap();
    let pub_key = b64_url_encode(pub_key.as_bytes());

    let priv_key = ud.priv_key.to_pkcs1_der().unwrap();
    let enc_priv_key = aes256_gcm_encrypt(
        priv_key.as_bytes(),
        ud.auk.0.as_slice(),
        &['A' as u8, '3' as u8],
    );
    let enc_priv_key = enc_priv_key.to_b64();

    let sud = SerializedUserData {
        email,
        account_string,
        auk_gen_params,
        srp_gen_params,
        enc_srp,
        pub_key,
        enc_priv_key,
    };

    persist_serialized_user_data(&sud)
}

fn load_serialized_user_data(email: &str) -> Result<SerializedUserData> {
    let home = home::home_dir().unwrap();
    let path = home
        .join(".kelkaj-pasvortoj")
        .join(format!("{}.json", email));

    let file = match File::open(&path) {
        Ok(file) => file,
        Err(err) => return Err(anyhow!("could not read file: {}, {}", path.display(), err)),
    };

    let decoded: SerializedUserData = serde_json::from_reader(&file)?;

    Ok(decoded)
}

pub fn load_user_data(raw_email: &str, password: String) -> Result<UserData> {
    let email = NormalizedEmail::new(raw_email.to_string());
    let serialized = load_serialized_user_data(&email.0)?;
    let password = NormalizedPassword::new(password);
    let account_id = serialized.account_string.substring(2, 8).to_string();
    let secret_key = serialized.account_string.substring(8, 34);
    let secret_key = SecretKey(AutoZeroedByteArray::new(secret_key.as_bytes().to_vec()));

    let auk_salt = b64_url_decode(&serialized.auk_gen_params.salt).unwrap();
    let auk_salt = Salt(AutoZeroedByteArray::new(auk_salt));

    let auk =
        AccountUnlockKey::from_user_info(&password, &secret_key, &auk_salt, &email, &account_id);

    let enc_srp = Aes256GcmEncryptedData::from_b64(serialized.enc_srp)?;

    // let srpx = aes256_gcm_decrypt(&enc_srp, auk.0.as_slice(), Some(&['A' as u8, '3' as u8]));
    let srpx = aes256_gcm_decrypt(enc_srp, auk.0.as_slice(), Some(&['A' as u8, '3' as u8]));
    let srpx = match srpx {
        Ok(bytes) => bytes,
        Err(err) => return Err(anyhow!("Failed to decrypt SRP-x: {}", err)),
    };
    let srpx = SecureRemotePasswordSecret(AutoZeroedByteArray::new(srpx));
    let srp_salt = b64_url_decode(&serialized.srp_gen_params.salt).unwrap();
    let srp_salt = Salt(AutoZeroedByteArray::new(srp_salt));

    let pub_key = b64_url_decode(&serialized.pub_key).unwrap();
    let pub_key: RsaPublicKey = DecodeRsaPublicKey::from_pkcs1_der(pub_key.as_slice()).unwrap();
    let enc_priv_key = Aes256GcmEncryptedData::from_b64(serialized.enc_priv_key)?;

    let priv_key = aes256_gcm_decrypt(enc_priv_key, auk.0.as_slice(), Some(&['A' as u8, '3' as u8]));
    let priv_key = match priv_key {
        Ok(bytes) => bytes,
        Err(err) => return Err(anyhow!("Failed to decrypt private key: {}", err)),
    };
    let priv_key: RsaPrivateKey = DecodeRsaPrivateKey::from_pkcs1_der(priv_key.as_slice()).unwrap();

    Ok(UserData {
        email: raw_email.to_string(),
        secret_key,
        account_id,
        auk,
        auk_salt,
        srpx,
        srp_salt,
        pub_key,
        priv_key,
    })
}

#[cfg(test)]
#[test]
fn user_data_persistence_test() {
    use shared::flows::generate_registration_info;

    let email = "test@localhost";

    // We send that to the server, which generates a registration token,
    // which would ultimately give us an account ID
    let account_id = "AAAAAA";

    // Then we pick a password and generate our key material
    let password = "password";
    let reg_info = generate_registration_info(password, email, account_id);

    let user_data = UserData {
        email: email.to_string(),
        secret_key: reg_info.secret,
        account_id: account_id.to_string(),
        auk: reg_info.auk,
        auk_salt: reg_info.encryption_key_salt,
        srpx: reg_info.srp,
        srp_salt: reg_info.authentication_salt,
        pub_key: reg_info.public_key,
        priv_key: reg_info.private_key,
    };

    let save_result = save_user_data(&user_data);
    println!("{:?}", save_result);
    assert!(save_result.is_ok());

    let loaded = load_user_data(email, password.to_string());
    assert!(loaded.is_ok());
}

#[derive(Serialize, Deserialize)]
struct SerializedSession {
    id: uuid::Uuid,
    email: String,
    shared_secret: String,
}

pub struct Session {
    pub id: uuid::Uuid,
    pub email: String,
    pub shared_secret: AutoZeroedByteArray,
}

pub fn save_session(session: &Session) -> Result<()> {
    let ss = SerializedSession {
        id: session.id,
        email: session.email.clone(),
        shared_secret: b64_url_encode(session.shared_secret.as_slice()),
    };

    let json = json!(ss).to_string();

    let home = home::home_dir().unwrap();
    let path = home.join(".kelkaj-pasvortoj").join("session.json");

    let mut file = match File::create(&path) {
        Err(why) => return Err(anyhow!("couldn't create {}: {}", path.display(), why)),
        Ok(file) => file,
    };

    match file.write_all(json.as_bytes()) {
        Err(why) => Err(anyhow!("couldn't write to {}: {}", path.display(), why)),
        Ok(_) => Ok(()),
    }
}

pub fn load_session(email: &str) -> Result<Session> {
    let home = home::home_dir().unwrap();
    let path = home.join(".kelkaj-pasvortoj").join("session.json");

    let file = match File::open(&path) {
        Ok(file) => file,
        Err(err) => return Err(anyhow!("could not read file: {}, {}", path.display(), err)),
    };

    let decoded: SerializedSession = serde_json::from_reader(&file)?;

    Ok(Session {
        id: decoded.id,
        email: decoded.email,
        shared_secret: AutoZeroedByteArray::new(
            b64_url_decode(&decoded.shared_secret).unwrap(),
        ),
    })
}
