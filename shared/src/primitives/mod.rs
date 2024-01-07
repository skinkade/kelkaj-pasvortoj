use serde::{Serialize, Deserialize};
use unicode_normalization::UnicodeNormalization;
use std::fmt::Display;
use crate::crypto::crypt_rand_uniform;

pub fn zero_byte_array(arr: &mut Vec<u8>) {
    for i in 0..arr.len() {
        arr[i] = 0;
    }
}

pub struct AutoZeroedByteArray(Vec<u8>);

impl AutoZeroedByteArray {
    pub fn new(bytes: Vec<u8>) -> AutoZeroedByteArray {
        AutoZeroedByteArray(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Drop for AutoZeroedByteArray {
    fn drop(&mut self) {
        zero_byte_array(&mut self.0)
    }
}

pub struct NormalizedPassword(pub AutoZeroedByteArray);

impl NormalizedPassword {
    pub fn new(str: String) -> NormalizedPassword {
        let normalized: String = str.trim().nfkd().collect();
        let arr = AutoZeroedByteArray(normalized.as_bytes().to_vec());
        NormalizedPassword(arr)
    }
}

pub struct NormalizedEmail(pub String);

impl NormalizedEmail {
    pub fn new(str: String) -> NormalizedEmail {
        NormalizedEmail(str.trim().to_lowercase())
    }
}

pub struct SecretKey(pub AutoZeroedByteArray);

impl SecretKey {
    pub fn generate_random(account_id: &str) -> SecretKey {
        let key_mask: Vec<char> = "23456789ABCDEFGHJKLMNPQRSTVWXYZ".chars().collect();
        let key_mask_len: u32 = key_mask.len() as u32;


        let mut account_id: Vec<char> = account_id.chars().collect();
        let mut new_key: Vec<char> = (0..26).map(|_| key_mask[crypt_rand_uniform(key_mask_len) as usize]).collect();
        
        // let mut overall_key = vec!['A', '3'];
        // overall_key.append(&mut account_id);
        // overall_key.append(&mut new_key);
        let overall_key: Vec<u8> = new_key.iter().map(|c| *c as u8).collect();

        SecretKey(AutoZeroedByteArray(overall_key))
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str: String = self.0.0.iter().map(|byte| *byte as char).collect();
        // TODO: dashes, e.g. A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB
        write!(f, "{}", str)
    }
}

// "AUK"
pub struct AccountUnlockKey(pub AutoZeroedByteArray);

// "SRP-x"
pub struct SecureRemotePasswordSecret(pub AutoZeroedByteArray);

pub struct Salt(pub Vec<u8>);

pub struct SrpVerifier(pub AutoZeroedByteArray);

#[derive(Debug, Serialize, Deserialize)]
pub struct Pbkdf2Params {
    pub algo: String,
    pub salt: String,
    pub iterations: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Aes256GcmEncryptedData {
    pub ciphertext: String,
    pub iv: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultOverview {
    pub title: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultDetails {
    pub description: String,
}