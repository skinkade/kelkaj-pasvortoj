use base64::{engine::general_purpose, Engine};
use clap::{Args, Parser, Subcommand};
use pkcs1::EncodeRsaPublicKey;
use serde_json::json;
use sha2::Sha256;
use shared::{
    crypto::{aes256_gcm_encrypt, finalize_srp_exchange, generate_client_srp_exchange_value},
    flows::{
        generate_registration_info, LoginHandshakeConfirmation, LoginHandshakeConfirmationResponse,
        LoginHandshakeConfirmationValue, LoginHandshakeStart, LoginHandshakeStartResponse,
        RegistrationCompletionRequest, RegistrationInitiationRequest,
    }, primitives::{Pbkdf2Params, Aes256GcmEncryptedData, NormalizedPassword, AutoZeroedByteArray, VaultOverview, VaultDetails}, rsa::Oaep,
};
use std::{io::{self, BufRead, Write}, fmt::format};
use rand::{rngs::OsRng, RngCore};

use crate::persistence::{UserData, Session};
mod persistence;

#[derive(Args, Debug)]
struct RegisterInput {
    email: String,
}

#[derive(Args, Debug)]
struct LoginInput {
    email: String,
}

#[derive(Subcommand, Debug)]
enum Subcommands {
    Register(RegisterInput),
    Login(LoginInput)
}

#[derive(Parser, Debug)]
struct Arguments {
    #[command(subcommand)]
    command: Subcommands,
}

async fn register(email: &str) {
    let client = reqwest::Client::new();
    let reg_body = RegistrationInitiationRequest {
        email: email.to_string(),
    };
    println!("Sending registration request...");
    let resp = client
        .post("http://localhost:3000/invites/create")
        .json(&reg_body)
        .send()
        .await
        .unwrap();
    println!("Sent! Check backend console for the following:");

    print!("Invitation ID: ");
    let _ = io::stdout().flush();
    let mut invite_id = String::new();
    let _ = io::stdin().read_line(&mut invite_id);
    let invite_id = invite_id.trim().to_owned();

    print!("Acceptance token: ");
    let _ = io::stdout().flush();
    let mut acceptance_token = String::new();
    let _ = io::stdin().read_line(&mut acceptance_token);
    let acceptance_token = acceptance_token.trim().to_owned();

    print!("Account ID: ");
    let _ = io::stdout().flush();
    let mut account_id = String::new();
    let _ = io::stdin().read_line(&mut account_id);
    let account_id = account_id.trim().to_owned();

    print!("And now choose your password: ");
    let _ = io::stdout().flush();
    let mut password = String::new();
    let _ = io::stdin().lock().read_line(&mut password);

    let registration_info = generate_registration_info(&password, &email, &account_id);

    let mut rng = rand::thread_rng();
    let mut vault_key = [0u8; 32];
    rng.fill_bytes(&mut vault_key);

    let padding = Oaep::new::<Sha256>();

    let enc_vault_key = registration_info.public_key.encrypt(&mut rng, padding, &vault_key).unwrap();

    let vault_overview = VaultOverview {
        title: "Default Vault".to_string()
    };
    let enc_vault_overview = aes256_gcm_encrypt(json!(vault_overview).to_string().as_bytes(), &vault_key, &[]).to_b64();

    let vault_details = VaultDetails {
        description: format!("Default vault belonging to {}", email)
    };
    let enc_vault_details = aes256_gcm_encrypt(json!(vault_details).to_string().as_bytes(), &vault_key, &[]).to_b64();

    let confirmation = RegistrationCompletionRequest {
        invite_id: uuid::Uuid::parse_str(&invite_id).unwrap(),
        acceptance_token,
        auk_params: Pbkdf2Params {
            iterations: 650_000,
            salt: general_purpose::STANDARD.encode(&registration_info.encryption_key_salt.0),
            algo: "PBKDF2-HMAC-SHA256".to_string()
        },
        srp_verifier: general_purpose::STANDARD.encode(registration_info.srp_verifier.0.as_slice()),
        srp_params: Pbkdf2Params {
            iterations: 650_000,
            salt: general_purpose::STANDARD.encode(&registration_info.authentication_salt.0),
            algo: "PBKDF2-HMAC-SHA256".to_string()
        },
        public_key: general_purpose::STANDARD.encode(
            registration_info
                .public_key
                .to_pkcs1_der()
                .unwrap()
                .as_bytes(),
        ),
        enc_priv_key: Aes256GcmEncryptedData {
            iv: general_purpose::STANDARD.encode(&registration_info.encrypted_private_key_iv),
            ciphertext: general_purpose::STANDARD.encode(&registration_info.encrypted_private_key)
        },
        enc_vault_overview,
        enc_vault_details,
        enc_vault_key: general_purpose::STANDARD.encode(&enc_vault_key)
    };

    let resp = client
        .post("http://localhost:3000/invites/accept")
        .json(&confirmation)
        .send()
        .await
        .unwrap();
    // println!("{:?}", resp);
    // println!("{:?}", resp.text().await.unwrap());

    let ud = UserData {
        email: email.to_string(),
        secret_key: registration_info.secret,
        account_id,
        auk: registration_info.auk,
        auk_salt: registration_info.encryption_key_salt,
        srpx: registration_info.srp,
        srp_salt: registration_info.authentication_salt,
        pub_key: registration_info.public_key,
        priv_key: registration_info.private_key,
    };
    persistence::save_user_data(&ud);
    println!("Registration successful!");
}

async fn login(email: String) {
    print!("Password: ");
    let _ = io::stdout().flush();
    let mut password = String::new();
    let _ = io::stdin().lock().read_line(&mut password);
    let password = password.trim().to_owned();

    let ud = persistence::load_user_data(&email, password).unwrap();
    
    let srp_values = generate_client_srp_exchange_value();
    let login = LoginHandshakeStart {
        a_pub: general_purpose::STANDARD.encode(srp_values.a_pub),
        email: email.to_owned(),
        account_id: ud.account_id,
    };

    let client = reqwest::Client::new();
    let start_resp = client
        .post("http://localhost:3000/login/begin")
        .json(&login)
        .send()
        .await
        .unwrap();
    let login_resp: LoginHandshakeStartResponse = start_resp.json().await.unwrap();
    let finalized = finalize_srp_exchange(
        &ud.srpx,
        srp_values.a.as_slice(),
        &general_purpose::STANDARD.decode(login_resp.b_pub).unwrap(),
    );
    let shared_secret = shared::crypto::hashing::sha256(&finalized);
    // println!("Shared secret: {:?}", shared_secret);

    let encrypted_confirmation =
        aes256_gcm_encrypt(login_resp.handshake_id.as_bytes(), &shared_secret, &[]);

    let confirmation_req = LoginHandshakeConfirmation {
        handshake_id: login_resp.handshake_id,
        confirmation: LoginHandshakeConfirmationValue {
            iv: general_purpose::STANDARD.encode(&encrypted_confirmation.iv),
            ciphertext: general_purpose::STANDARD.encode(&encrypted_confirmation.ciphertext),
        },
    };

    let confirmation_resp = client
        .post("http://localhost:3000/login/confirm")
        .json(&confirmation_req)
        .send()
        .await
        .unwrap();

    let confirmation: LoginHandshakeConfirmationResponse = confirmation_resp.json().await.unwrap();
    println!("Session: {:?}", confirmation.session_id);
    persistence::save_session(&Session {
        id: confirmation.session_id,
        shared_secret: AutoZeroedByteArray::new(shared_secret),
        email: email.to_string()
    }).unwrap()
}

#[tokio::main]
async fn main() {
    let args = Arguments::parse();

    match args.command {
        Subcommands::Register(input) => {
            register(&input.email).await;
        },
        Subcommands::Login(input) => {
            login(input.email).await
        }
    }
}
