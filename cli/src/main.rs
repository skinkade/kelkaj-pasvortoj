use clap::{Args, Parser, Subcommand};
use pkcs1::{EncodeRsaPublicKey, DecodeRsaPrivateKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use shared::{
    crypto::{
        aes256_gcm_decrypt, aes256_gcm_encrypt, finalize_srp_exchange,
        generate_client_srp_exchange_value,
    },
    flows::{
        generate_registration_info, LoginHandshakeConfirmation, LoginHandshakeConfirmationResponse,
        LoginHandshakeConfirmationValue, LoginHandshakeStart, LoginHandshakeStartResponse,
        RegistrationCompletionRequest, RegistrationInitiationRequest,
    },
    primitives::{
        Aes256GcmEncryptedDataB64, AutoZeroedByteArray, NormalizedPassword, Pbkdf2Params,
        VaultDetails, VaultOverview, Aes256GcmEncryptedData,
    },
    rpc::{EncryptedRpcPayload, RpcPayload, CreateVaultEntryPayload},
    rsa::{Oaep, RsaPrivateKey}, utils::{b64_url_decode, b64_url_encode},
};
use std::{
    fmt::format,
    io::{self, BufRead, Write},
};

use crate::persistence::{Session, UserData};
mod persistence;

#[derive(Args, Debug)]
struct RegisterInput {
    email: String,
}

#[derive(Args, Debug)]
struct LoginInput {
    email: String,
}

#[derive(Args, Debug)]
struct GetDefaultVaultInput {
    email: String,
}

#[derive(Args, Debug)]
struct AddVaultItemInput {
    email: String,
}

#[derive(Subcommand, Debug)]
enum Subcommands {
    Register(RegisterInput),
    Login(LoginInput),
    GetDefaultVault(GetDefaultVaultInput),
    AddVaultItem(AddVaultItemInput)
}

#[derive(Parser, Debug)]
struct Arguments {
    #[command(subcommand)]
    command: Subcommands,
}


#[derive(Serialize, Deserialize, Debug)]
struct VaultItemOverview {
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct VaultItemDetails {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct EncryptedVaultItem {
    pub id: uuid::Uuid,
    pub enc_overview: Aes256GcmEncryptedDataB64,
    pub enc_details: Aes256GcmEncryptedDataB64,
}

#[derive(Debug, Deserialize)]
pub struct EncryptedVault {
    pub id: uuid::Uuid,
    pub enc_overview: Aes256GcmEncryptedDataB64,
    pub enc_details: Aes256GcmEncryptedDataB64,
    pub enc_vault_key: String,
    pub items: Vec<EncryptedVaultItem>,
}

#[derive(Debug)]
pub struct VaultItem {
    pub id: uuid::Uuid,
    pub overview: VaultItemOverview,
    pub details: VaultItemDetails,
}

#[derive(Debug)]
struct Vault {
    pub id: uuid::Uuid,
    pub key: AutoZeroedByteArray,
    pub overview: VaultOverview,
    pub details: VaultDetails,
    pub items: Vec<VaultItem>
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

    let enc_vault_key = registration_info
        .public_key
        .encrypt(&mut rng, padding, &vault_key)
        .unwrap();

    let vault_overview = VaultOverview {
        title: "Default Vault".to_string(),
    };
    let enc_vault_overview = aes256_gcm_encrypt(
        json!(vault_overview).to_string().as_bytes(),
        &vault_key,
        &[],
    )
    .to_b64();

    let vault_details = VaultDetails {
        description: format!("Default vault belonging to {}", email),
    };
    let enc_vault_details =
        aes256_gcm_encrypt(json!(vault_details).to_string().as_bytes(), &vault_key, &[]).to_b64();

    let confirmation = RegistrationCompletionRequest {
        invite_id: uuid::Uuid::parse_str(&invite_id).unwrap(),
        acceptance_token,
        auk_params: Pbkdf2Params {
            iterations: 650_000,
            salt: b64_url_encode(registration_info.encryption_key_salt.0.as_slice()),
            algo: "PBKDF2-HMAC-SHA256".to_string(),
        },
        srp_verifier: b64_url_encode(registration_info.srp_verifier.0.as_slice()),
        srp_params: Pbkdf2Params {
            iterations: 650_000,
            salt: b64_url_encode(registration_info.authentication_salt.0.as_slice()),
            algo: "PBKDF2-HMAC-SHA256".to_string(),
        },
        public_key: b64_url_encode(
            registration_info
                .public_key
                .to_pkcs1_der()
                .unwrap()
                .as_bytes(),
        ),
        enc_priv_key: registration_info.encrypted_private_key.to_b64(),
        enc_vault_overview,
        enc_vault_details,
        enc_vault_key: b64_url_encode(&enc_vault_key),
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
        a_pub: b64_url_encode(&srp_values.a_pub),
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
        &b64_url_decode(&login_resp.b_pub).unwrap(),
    );
    let shared_secret = shared::crypto::hashing::sha256(&finalized);
    // println!("Shared secret: {:?}", shared_secret);

    let encrypted_confirmation =
        aes256_gcm_encrypt(login_resp.handshake_id.as_bytes(), &shared_secret, &[]);

    let confirmation_req = LoginHandshakeConfirmation {
        handshake_id: login_resp.handshake_id,
        confirmation: LoginHandshakeConfirmationValue {
            iv: b64_url_encode(encrypted_confirmation.iv.as_slice()),
            ciphertext: b64_url_encode(encrypted_confirmation.ciphertext.as_slice()),
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
        email: email.to_string(),
    })
    .unwrap()
}

async fn get_default_vault_and_current_session(email: &str) -> (Vault, Session) {
    print!("Account password: ");
    let _ = io::stdout().flush();
    let mut password = String::new();
    let _ = io::stdin().lock().read_line(&mut password);
    let password = password.to_owned();

    let ud = persistence::load_user_data(email, password).unwrap();
    let session = persistence::load_session(email).unwrap();

    let payload = json!(RpcPayload {
        command: "get-default-vault/v1".to_string(),
        parameters: "{}".to_string()
    })
    .to_string();
    let payload = EncryptedRpcPayload {
        payload: aes256_gcm_encrypt(payload.as_bytes(), session.shared_secret.as_slice(), &[])
            .to_b64(),
    };

    let client = reqwest::Client::new();
    let resp = client
        .post("http://localhost:3000/rpc")
        .json(&payload)
        .header("session", session.id.to_string())
        .send()
        .await
        .unwrap();
    println!("{:?}", resp);

    let resp_payload: EncryptedRpcPayload = resp.json().await.unwrap();
    let resp_payload = Aes256GcmEncryptedData::from_b64(resp_payload.payload).unwrap();

    let resp_payload = aes256_gcm_decrypt(resp_payload, session.shared_secret.as_slice(), None).unwrap();

    let enc_vault: EncryptedVault  = serde_json::from_slice(&resp_payload).unwrap();

    let padding = Oaep::new::<Sha256>();

    let vault_key = b64_url_decode(&enc_vault.enc_vault_key).unwrap();
    let vault_key = ud.priv_key.decrypt(padding, &vault_key).unwrap();

    let vault_overview = Aes256GcmEncryptedData::from_b64(enc_vault.enc_overview).unwrap();
    let vault_overview = aes256_gcm_decrypt(vault_overview, &vault_key, None).unwrap();
    let vault_overview: VaultOverview = serde_json::from_slice(&vault_overview).unwrap();
    
    let vault_details = Aes256GcmEncryptedData::from_b64(enc_vault.enc_details).unwrap();
    let vault_details = aes256_gcm_decrypt(vault_details, &vault_key, None).unwrap();
    let vault_details: VaultDetails = serde_json::from_slice(&vault_details).unwrap();

    let items: Vec<VaultItem> = enc_vault.items.iter().map(|item| {
        let overview = Aes256GcmEncryptedData::from_b64(item.enc_overview.clone()).unwrap();
        let overview = aes256_gcm_decrypt(overview, &vault_key, None).unwrap();
        let overview: VaultItemOverview = serde_json::from_slice(&overview).unwrap();

        let details = Aes256GcmEncryptedData::from_b64(item.enc_details.clone()).unwrap();
        let details = aes256_gcm_decrypt(details, &vault_key, None).unwrap();
        let details: VaultItemDetails = serde_json::from_slice(&details).unwrap();

        VaultItem {
            id: item.id,
            overview,
            details
        }
    }).collect();

    (Vault {
        id: enc_vault.id,
        key: AutoZeroedByteArray::new(vault_key),
        overview: vault_overview,
        details: vault_details,
        items
    }, session)
}

async fn add_vault_item(email: String) {
    let (vault, session) = get_default_vault_and_current_session(&email).await;

    print!("Item description: ");
    let _ = io::stdout().flush();
    let mut description = String::new();
    let _ = io::stdin().read_line(&mut description);
    let description = description.trim().to_owned();

    print!("Item username: ");
    let _ = io::stdout().flush();
    let mut username = String::new();
    let _ = io::stdin().read_line(&mut username);
    let username = username.trim().to_owned();

    print!("Item password: ");
    let _ = io::stdout().flush();
    let mut password = String::new();
    let _ = io::stdin().read_line(&mut password);
    let password = password.trim().to_owned();

    let overview = json!(VaultItemOverview { description }).to_string();
    let details = json!(VaultItemDetails {username, password}).to_string();

    let enc_overview = aes256_gcm_encrypt(overview.as_bytes(), vault.key.as_slice(), &[]).to_b64();
    let enc_details = aes256_gcm_encrypt(details.as_bytes(), vault.key.as_slice(), &[]).to_b64();

    let nested_payload = CreateVaultEntryPayload {
        vault_id: vault.id,
        enc_overview,
        enc_details
    };
    let nested_payload = json!(nested_payload).to_string();

    let payload = json!(RpcPayload {
        command: "create-vault-entry/v1".to_string(),
        parameters: nested_payload
    })
    .to_string();
    let payload = EncryptedRpcPayload {
        payload: aes256_gcm_encrypt(payload.as_bytes(), session.shared_secret.as_slice(), &[])
            .to_b64(),
    };

    let client = reqwest::Client::new();
    let resp = client
        .post("http://localhost:3000/rpc")
        .json(&payload)
        .header("session", session.id.to_string())
        .send()
        .await
        .unwrap();
    println!("{:?}", resp);
}

#[tokio::main]
async fn main() {
    let args = Arguments::parse();

    match args.command {
        Subcommands::Register(input) => register(&input.email).await,
        Subcommands::Login(input) => login(input.email).await,
        Subcommands::GetDefaultVault(input) => {
            let (vault, _) = get_default_vault_and_current_session(&input.email).await;
            println!("{:?}", vault)
        },
        Subcommands::AddVaultItem(input) => {
            add_vault_item(input.email).await
        }
    }
}
