pub mod hashing;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine};
use num_bigint::{self, BigUint, ToBigUint};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use srp::{
    client::SrpClient,
    groups::G_4096,
    server::SrpServer,
    utils::{compute_k, compute_u},
};

use crate::primitives::{AutoZeroedByteArray, SecureRemotePasswordSecret, SrpVerifier, Aes256GcmEncryptedData};

pub fn crypt_rand_uniform(upper_bound: u32) -> u32 {
    if upper_bound < 2 {
        return 0;
    }

    let upper_bound = upper_bound as u64;
    let min = 2u64.pow(32) % upper_bound;

    let mut r: u64;

    loop {
        r = OsRng.next_u64();
        if r >= min {
            break;
        }
    }

    (r % upper_bound) as u32
}

pub struct Aes256GcmOutput {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
}

impl Aes256GcmOutput {
    pub fn to_b64(&self) -> Aes256GcmEncryptedData {
        Aes256GcmEncryptedData {
            iv: general_purpose::STANDARD.encode(&self.iv),
            ciphertext: general_purpose::STANDARD.encode(&self.ciphertext)
        }
    }
}

pub fn aes256_gcm_encrypt(plaintext: &[u8], key: &[u8], additional_data: &[u8]) -> Aes256GcmOutput {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let payload = Payload {
        msg: plaintext,
        aad: additional_data,
    };

    let ciphertext = cipher.encrypt(&nonce, payload).unwrap();

    Aes256GcmOutput {
        ciphertext,
        iv: nonce.to_vec(),
    }
}

pub fn aes256_gcm_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(&key);

    let payload = Payload {
        msg: ciphertext,
        aad: additional_data,
    };

    cipher.decrypt(nonce, payload)
}

pub fn compute_srp_verifier(secret: &SecureRemotePasswordSecret) -> SrpVerifier {
    let client = SrpClient::<Sha256>::new(&G_4096);
    let v = client.compute_v(&BigUint::from_bytes_be(secret.0.as_slice()));

    SrpVerifier(AutoZeroedByteArray::new(v.to_bytes_be()))
}

pub struct SrpClientExchangeValues {
    pub a: AutoZeroedByteArray,
    pub a_pub: Vec<u8>,
}

pub fn generate_client_srp_exchange_value() -> SrpClientExchangeValues {
    let mut a = [0u8; 64];
    OsRng.fill_bytes(&mut a);

    let client = SrpClient::<Sha256>::new(&G_4096);
    let a_pub = client.compute_public_ephemeral(&a);

    SrpClientExchangeValues {
        a: AutoZeroedByteArray::new(a.to_vec()),
        a_pub,
    }
}

pub struct SrpServerExchangeValues {
    pub shared_secret: AutoZeroedByteArray,
    pub b: AutoZeroedByteArray,
    pub b_pub: Vec<u8>,
}

pub fn generate_server_srp_exchange_values(
    v: SrpVerifier,
    a_pub: Vec<u8>,
) -> SrpServerExchangeValues {
    // let a_pub = BigUint::from_bytes_be(&a_pub);
    let mut b = [0u8; 64];
    OsRng.fill_bytes(&mut b);

    let server = SrpServer::<Sha256>::new(&G_4096);
    let b_pub = server.compute_public_ephemeral(&b, v.0.as_slice());

    let verifier = server.process_reply(&b, v.0.as_slice(), &a_pub).unwrap();
    let shared_secret = verifier.key();

    SrpServerExchangeValues {
        shared_secret: AutoZeroedByteArray::new(shared_secret.to_vec()),
        b: AutoZeroedByteArray::new(b.to_vec()),
        b_pub,
    }
}

pub fn finalize_srp_exchange(x: &SecureRemotePasswordSecret, a: &[u8], b_pub: &[u8]) -> Vec<u8> {
    let b_pub = BigUint::from_bytes_be(b_pub);
    // Safeguard against malicious B
    if &b_pub % &G_4096.n == BigUint::default() {
        // return Err(SrpAuthError::IllegalParameter("b_pub".to_owned()));
        panic!("Potentially malicious B in SRP exchange")
    }

    let client = SrpClient::<Sha256>::new(&G_4096);
    let a_pub = client.compute_a_pub(&BigUint::from_bytes_be(a));
    let u = compute_u::<Sha256>(&a_pub.to_bytes_be(), &b_pub.to_bytes_be());
    let k = compute_k::<Sha256>(&G_4096);

    let key = client.compute_premaster_secret(
        &b_pub,
        &k,
        &BigUint::from_bytes_be(x.0.as_slice()),
        &BigUint::from_bytes_be(a),
        &u,
    );

    key.to_bytes_be()
}

// /// Computes SRP verifier `v` from secret `x`.
// /// Whitepaper p.83
// pub fn compute_srp_verifier(secret: &SecureRemotePasswordSecret) -> SrpVerifier {
//     let x = BigUint::from_bytes_le(secret.0.as_slice());
//     let v = G_4096.g.modpow(&x, &G_4096.n).to_bytes_le();

//     SrpVerifier(AutoZeroedByteArray::new(v))
// }

// pub struct SrpClientExchangeValues {
//     secret: AutoZeroedByteArray,
//     public: Vec<u8>,
// }

// pub fn generate_client_srp_exchange_value() -> SrpClientExchangeValues {
//     let mut a_bytes = [0u8; 32];
//     OsRng.fill_bytes(&mut a_bytes);
//     let a_num = BigUint::from_bytes_le(a_bytes.as_slice());

//     // A = g^a
//     let a_pub = G_4096.g.modpow(&a_num, &G_4096.n).to_bytes_le();

//     SrpClientExchangeValues {
//         secret: AutoZeroedByteArray::new(a_bytes.to_vec()),
//         public: a_pub,
//     }
// }

// pub struct SrpServerExchangeValues {
//     shared_secret: AutoZeroedByteArray,
//     secret: AutoZeroedByteArray,
//     public: Vec<u8>,
// }

// pub fn generate_server_srp_exchange_values(
//     verifier: SrpVerifier,
//     client_input: Vec<u8>,
// ) -> SrpServerExchangeValues {
//     let v = BigUint::from_bytes_le(&verifier.0.as_slice());
//     let a_pub = BigUint::from_bytes_le(&client_input);

//     let mut b_bytes = [0u8; 32];
//     OsRng.fill_bytes(&mut b_bytes);
//     let b_num = BigUint::from_bytes_le(&b_bytes);

//     // k = A^b
//     let k = a_pub.modpow(&b_num, &G_4096.n);

//     // B = kv + g^b
//     let b_pub = (k * v.clone()) + G_4096.g.modpow(&b_num, &G_4096.n);

//     let u_bytes = vec![client_input, b_pub.to_bytes_le()].concat();
//     let u_bytes = hashing::sha256(&u_bytes);
//     let u_num = BigUint::from_bytes_le(&u_bytes);

//     // S = (Av^u)^b
//     let big_s = (a_pub * v.clone().modpow(&u_num, &G_4096.n)).modpow(&b_num, &G_4096.n);

//     SrpServerExchangeValues {
//         shared_secret: AutoZeroedByteArray::new(big_s.to_bytes_le()),
//         secret: AutoZeroedByteArray::new(b_bytes.to_vec()),
//         public: b_pub.to_bytes_le(),
//     }
// }

// pub fn finalize_srp_exchange(
//     srp_secret: &SecureRemotePasswordSecret,
//     client_secret: &[u8],
//     server_public: &[u8],
// ) -> Vec<u8> {
//     let x = BigUint::from_bytes_le(srp_secret.0.as_slice());
//     let a = BigUint::from_bytes_le(client_secret);
//     let a_pub = G_4096.g.modpow(&a, &G_4096.n);
//     let b_pub = BigUint::from_bytes_le(&server_public);

//     let u_bytes = vec![a_pub.to_bytes_le(), server_public.to_vec()].concat();
//     let u_bytes = hashing::sha256(&u_bytes);
//     let u_num = BigUint::from_bytes_le(&u_bytes);

//     // k = B^a
//     let k = b_pub.modpow(&a, &G_4096.n);

//     // S = (B - kg^x)^(a+ux)
//     let aux = a + (u_num * x.clone());
//     let big_s = (b_pub - (k * G_4096.g.modpow(&x, &G_4096.n))).modpow(&aux, &G_4096.n);

//     big_s.to_bytes_le()
// }

#[cfg(test)]
#[test]
pub fn srp_exchange() {
    use crate::crypto::hashing::sha256;

    let mut x = [0u8; 32];
    OsRng.fill_bytes(&mut x);
    let x = SecureRemotePasswordSecret(AutoZeroedByteArray::new(x.to_vec()));
    let v = compute_srp_verifier(&x);

    let client_values = generate_client_srp_exchange_value();
    let server_values = generate_server_srp_exchange_values(v, client_values.a_pub);
    let finalized =
        finalize_srp_exchange(&x, client_values.a.as_slice(), &server_values.b_pub);

    let ref_a = hex::encode(sha256(server_values.shared_secret.as_slice()));
    let ref_b = hex::encode(sha256(&finalized));

    assert!(ref_a == ref_b);
}
